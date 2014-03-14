/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <thread>
#include <string>
#include <iostream>
#include <utility>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "address.hh"
#include "socket.hh"
#include "timestamp.hh"
#include "system_runner.hh"
#include "config.h"
#include "signalfd.hh"
#include "http_proxy.hh"
#include "poller.hh"
#include "bytestream_queue.hh"
#include "http_request_parser.hh"
#include "http_response_parser.hh"
#include "file_descriptor.hh"

using namespace std;
using namespace PollerShortNames;

HTTPProxy::HTTPProxy( const Address & listener_addr )
    : listener_socket_( TCP ),
      first_req( true )
{
    listener_socket_.bind( listener_addr );
    listener_socket_.listen();

    /* set starting seed for random number file names */
    srandom( time( NULL ) );

    /* SSL initialization: Needs to be done exactly once */
    /* load algorithms/ciphers */
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* load error messages */
    SSL_load_error_strings();
}

void HTTPProxy::handle_tcp( Archive & archive )
{
    thread newthread( [&] ( Socket client ) {
            try {
                /* get original destination for connection request */
                Address original_destaddr = client.original_dest();
                cout << "connection intended for: " << original_destaddr.ip() << endl;

                /* create socket and connect to original destination and send original request */
                Socket server( TCP );
                server.connect( original_destaddr );

                Poller poller;

                HTTPRequestParser request_parser;

                HTTPResponseParser response_parser;

                int already_sent = 0;

                auto dst_port = original_destaddr.port();

                /* Create Read/Write Interfaces for server and client */
                std::unique_ptr<ReadWriteInterface> server_rw  = (dst_port == 443) ?
                                                                 static_cast<decltype( server_rw )>( new SecureSocket( move( server ), CLIENT ) ) :
                                                                 static_cast<decltype( server_rw )>( new Socket( move( server ) ) );
                std::unique_ptr<ReadWriteInterface> client_rw  = (dst_port == 443) ?
                                                                 static_cast<decltype( client_rw )>( new SecureSocket( move( client ), SERVER ) ) :
                                                                 static_cast<decltype( client_rw )>( new Socket( move( client ) ) );
                /* Make bytestream_queue for browser->server and server->browser */
                ByteStreamQueue from_destination( ezio::read_chunk_size );

                /* poll on original connect socket and new connection socket to ferry packets */
                /* responses from server go to response parser */
                poller.add_action( Poller::Action( server_rw->fd(), Direction::In,
                                                   [&] () {
                                                       string buffer = server_rw->read();
                                                       response_parser.parse( buffer, archive, from_destination );
                                                       return ResultType::Continue;
                                                   },
                                                   [&] () { return ( not client_rw->fd().eof() ); } ) );

                /* requests from client go to request parser */
                poller.add_action( Poller::Action( client_rw->fd(), Direction::In,
                                                   [&] () {
                                                       string buffer = client_rw->read();
                                                       request_parser.parse( buffer );
                                                       return ResultType::Continue;
                                                   },
                                                   [&] () { return not server_rw->fd().eof(); } ) );

                /* completed requests from client are serialized and handled by archive or sent to server */
                poller.add_action( Poller::Action( server_rw->fd(), Direction::Out,
                                                   [&] () {
                                                       /* check if request is stored: if pending->wait, if response present->send to client, if neither->send request to server */
                                                       HTTP_Record::http_message complete_request = request_parser.front().toprotobuf();

                                                       if ( archive.request_pending( complete_request ) ) {
                                                           while ( archive.request_pending( complete_request ) ) { /* wait until we have the response filled in */
                                                               sleep( 1 );
                                                           }
                                                           if ( from_destination.contiguous_space_to_push() >= archive.corresponding_response( complete_request ).size() ) { /* we have space to add response */
                                                               from_destination.push_string( request_parser.front().str() );
                                                               request_parser.pop();
                                                           } else {
                                                               return ResultType::Continue;
                                                           }

                                                       } else if ( archive.have_response( complete_request ) ) { /* corresponding response already stored- send to client */
                                                           int avail_space = from_destination.contiguous_space_to_push();
                                                           int left_to_send = archive.corresponding_response( complete_request ).size() - already_sent;
                                                           if ( avail_space >= left_to_send ) { /* enough space to send rest of message */
                                                               from_destination.push_string( archive.corresponding_response( complete_request ).substr( already_sent, left_to_send ) );
                                                               already_sent = 0;
                                                               request_parser.pop();
                                                           } else if (avail_space < left_to_send and avail_space > 0 ) { /* space for some but not all */
                                                               from_destination.push_string( archive.corresponding_response( complete_request ).substr( already_sent, avail_space ) );
                                                               already_sent = already_sent + avail_space;
                                                           } else { /* avail_space is 0 */
                                                               assert( avail_space == 0 );
                                                               return ResultType::Continue;
                                                           }
                                                       } else { /* request not listed in archive- send request to server */
                                                           server_rw->write( request_parser.front().str() );
                                                           response_parser.new_request_arrived( request_parser.front() );
                                                           request_parser.pop();
                                                       }
                                                       return ResultType::Continue;
                                                   },
                                                   [&] () { return not request_parser.empty(); } ) );

                /* completed responses from server are serialized and sent to client along with complete responses in the bytestreamqueue */
                poller.add_action( Poller::Action( client_rw->fd(), Direction::Out,
                                                   [&] () {
                                                       if ( from_destination.non_empty() ) {
                                                           if ( dst_port == 443 ) {
                                                               from_destination.pop_ssl( move( client_rw ) );
                                                           } else {
                                                               from_destination.pop( client_rw->fd() );
                                                           }
                                                       }
                                                       if ( not response_parser.empty() ) {
                                                           client_rw->write( response_parser.front().str() );
                                                           response_parser.pop();
                                                       }
                                                       return ResultType::Continue;
                                                   },
                                                   [&] () { return (from_destination.non_empty() or ( not response_parser.empty() ) ); } ) );

                while( true ) {
                    auto poll_result = poller.poll( 60000 );
                    if ( poll_result.result == Poller::Result::Type::Exit ) {
                        return;
                    }
                }
            } catch ( const Exception & e ) {
                e.perror();
                return;
            }
            return;
        }, listener_socket_.accept() );

    /* don't wait around for the reply */
    newthread.detach();
}
