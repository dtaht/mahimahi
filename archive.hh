/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string>
#include <vector>
#include <utility>
#include <iostream>
#include <condition_variable>
#include <thread>
#include <mutex>
#include <deque>

#include "http_record.pb.h"

#ifndef ARCHIVE_HH
#define ARCHIVE_HH

static const std::string default_filename_template = "apache_config";

class Archive
{
private:
    std::vector< std::pair< HTTP_Record::http_message, std::string > > pending_ {};

    std::vector< std::unique_ptr< std::mutex > > mutexes_ {};

    std::vector< std::unique_ptr< std::condition_variable >  > cvs_ {};

    std::string get_corresponding_response( const HTTP_Record::http_message & new_req );

public:
    Archive() {};

    /* Add a request */
    void add_request( const HTTP_Record::http_message & request );

    /* Add a response */
    void add_response( const std::string & response, const size_t position );

    /* Do we have a matching request that is pending? */
    bool request_pending( const HTTP_Record::http_message & new_req );

    /* Do we have a stored response for this request? */
    bool have_response( const HTTP_Record::http_message & new_req );

    /* Return the corresponding response to the stored request (caller should first call have_response) */ 
    std::string corresponding_response( const HTTP_Record::http_message & new_req );

    int get_index( const HTTP_Record::http_message & new_req );

    size_t num_of_requests( void ) { return pending_.size(); }

    void waits( int index );

    void signals( int index );

    bool has_first_response( void )
    {
//        std::cout << "PENDING SIZE: " << pending_.size() << " second: " << pending_.at(0).second << std::endl;
        if ( pending_.size() > 0 and pending_.at(0).second != "pending" ) {
            return true;
        }
        return false;
    }

    std::string first_response( void ) { return pending_.at(0).second; }
};

#endif
