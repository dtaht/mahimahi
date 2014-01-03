/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <memory>
#include <csignal>

#include <iostream>
#include <vector>
#include <dirent.h>

#include "util.hh"
#include "system_runner.hh"
#include "http_record.pb.h"
#include "http_header.hh"
#include "exception.hh"

using namespace std;

/*
Find request headers in environment variables
For each stored req/res pair:
For each request header present in env and stored request, compare values until we find a match or difference
Consider: HTTP_ACCEPT, HTTP_ACCEPT_ENCODING, HTTP_ACCEPT_LANGUAGE, HTTP_CONNECTION,
          HTTP_COOKIE, HTTP_HOST, HTTP_REFERER, HTTP_USER_AGENT
If difference, move on to next one.
If all considered/existent headers match, write the response.
*/

void list_files( const string & dir, vector< string > & files )
{
    DIR *dp;
    struct dirent *dirp;

    if( ( dp  = opendir( dir.c_str() ) ) == NULL ) {
        throw Exception( "opendir" );
    }

    while ( ( dirp = readdir( dp ) ) != NULL ) {
        if ( string( dirp->d_name ) != "." and string( dirp->d_name ) != ".." ) {
            files.push_back( dir + string( dirp->d_name ) );
        }
    }
    SystemCall( "closedir", closedir( dp ) );
}

/* compare specific env header value and stored header value (if one does not exist, return true) */
bool check_headers( const string & env_header, const string & stored_header, HTTP_Record::http_message & saved_req )
{
    string env_value;
    if ( getenv( env_header.c_str() ) == NULL ) {
        return true;
    }

    /* environment header was passed to us */
    env_value = string( getenv( env_header.c_str() ) );
    for ( int i = 0; i < saved_req.headers_size(); i++ ) {
        HTTPHeader current_header( saved_req.headers(i) );
        if ( current_header.key() == stored_header ) { /* compare to environment variable */
            if ( current_header.value().substr( 0, current_header.value().find( "\r\n" ) ) == getenv( env_header.c_str() ) ) {
                return true;
            } else {
                return false;
            }
        }
    }
    /* environment header not in stored header */
    return true;
}

/* compare request_line and certain headers of incoming request and stored request */
bool compare_requests( HTTP_Record::reqrespair & saved_record, vector< HTTP_Record::reqrespair > possible_matches )
{
    HTTP_Record::http_message saved_req = saved_record.req();

    /* request line */
    string new_req = string( getenv( "REQUEST_METHOD" ) ) + " " + string( getenv( "REQUEST_URI" ) ) + " " + string ( getenv( "SERVER_PROTOCOL" ) ) + "\r\n";

    /* if query string present, compare. if not a match but object name matches, add to possibilities */
    uint64_t query_loc = saved_req.first_line().find( "?" );
    if ( query_loc == std::string::npos ) { /* no query string */
        if ( not ( new_req == saved_req.first_line() ) ) {
            return false;
        }
    } else { /* query string present */
        if ( not ( new_req == saved_req.first_line() ) ) {
            string no_query = string( getenv( "REQUEST_METHOD" ) ) + " " + string( getenv( "SCRIPT_URI" ) ) + " " + string ( getenv( "SERVER_PROTOCOL" ) ) + "\r\n";
            if ( no_query == saved_req.first_line().substr( 0, query_loc ) ) { /* request w/o query string matches */
                possible_matches.emplace_back( saved_record );
            }
            return false;
        }
    } 

    /* compare existing environment variables for request to stored header values */
    if ( not check_headers( "HTTP_ACCEPT_ENCODING", "Accept_Encoding", saved_req ) ) { return false; }
    if ( not check_headers( "HTTP_ACCEPT_LANGUAGE", "Accept_Language", saved_req ) ) { return false; }
    //if ( not check_headers( "HTTP_CONNECTION", "Connection", saved_req ) ) { return false; }
    //if ( not check_headers( "HTTP_COOKIE", "Cookie", saved_req ) ) { return false; }
    if ( not check_headers( "HTTP_HOST", "Host", saved_req ) ) { return false; }
    if ( not check_headers( "HTTP_REFERER", "Referer", saved_req ) ) { return false; }
    //if ( not check_headers( "HTTP_USER_AGENT", "User-Agent", saved_req ) ) { return false; }

    return true;
}

void return_message( const HTTP_Record::reqrespair & record )
{
    cout << record.res().first_line();
    for ( int j = 0; j < record.res().headers_size(); j++ ) {
        cout << record.res().headers( j );
    }
    cout << record.res().body() << endl;
}

int main()
{
    try {
        //cout << "Content-Type: text/html\r\n\r\n";
        /* print all environment variables */
        /*extern char **environ;
        for(char **current = environ; *current; current++) {
            cout << *current << endl << "<br />\n";
        }*/
        vector< string > files;
        list_files( "/home/ravi/mahimahi/cnn/", files );
        vector< HTTP_Record::reqrespair > possible_matches;
        unsigned int i;
        for ( i = 0; i < files.size(); i++ ) { /* iterate through files and call method which compares requests */
            int fd = SystemCall( "open", open( files[i].c_str(), O_RDONLY ) );
            HTTP_Record::reqrespair current_record;
            current_record.ParseFromFileDescriptor( fd );
            if ( compare_requests( current_record, possible_matches ) ) { /* requests match */
                return_message( current_record );
                SystemCall( "close", close( fd ) );
                break;
            }
            SystemCall( "close", close( fd ) );
        }
        if ( i == files.size() ) { /* no exact matches for request */
            if ( possible_matches.size() == 0 ) {
                throw Exception( "replaymyserver", "Can't find: " + string( getenv( "REQUEST_METHOD" ) ) + " " + string( getenv( "REQUEST_URI" ) ) );
                return EXIT_FAILURE;
            } else { /* for now, return first stored possibility */
                return_message( possible_matches.at( 0 ) );
                throw Exception( "replaymyserver", "Had to choose randomly for: " + string( getenv( "REQUEST_URI" ) ) );
            }
        }
    } catch ( const Exception & e ) {
        e.perror();
        return EXIT_FAILURE;
    }
}