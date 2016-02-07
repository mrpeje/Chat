/*#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "../../chat_message.hpp"
using namespace boost::asio;
io_service service;

#define MEM_FN(x)       boost::bind(&self_type::x, shared_from_this())
#define MEM_FN1(x,y)    boost::bind(&self_type::x, shared_from_this(),y)
#define MEM_FN2(x,y,z)  boost::bind(&self_type::x, shared_from_this(),y,z)

     simple connection to server:
    - logs in just with username (no password)
    - all connections are initiated by the client: client asks, server answers
    - server disconnects any client that hasn't pinged for 5 seconds
    Possible requests:
    - gets a list of all connected clients
    - ping: the server answers either with "ping ok" or "ping client_list_changed"

class talk_to_svr : public boost::enable_shared_from_this<talk_to_svr>
                  , boost::noncopyable {
    typedef talk_to_svr self_type;

    talk_to_svr(const std::string & username)
      : sock_(service), started_(true), username_(username), timer_(service) {}

    void start(ip::tcp::endpoint ep) {
        sock_.async_connect(ep, MEM_FN1(on_connect,_1));
    }
public:
    typedef boost::system::error_code error_code;
    typedef boost::shared_ptr<talk_to_svr> ptr;

    static ptr start(ip::tcp::endpoint ep, const std::string & username) {
        ptr new_(new talk_to_svr(username));
        new_->start(ep);
        return new_;
    }
    void stop() {
        if ( !started_) return;
        std::cout << "stopping " << username_ << std::endl;
        started_ = false;
        sock_.close();
    }
    bool started() { return started_; }
private:
    void on_connect(const error_code & err) {
        if ( !err)      do_write("login " + username_ + "\n");
        else            stop();
    }
    void on_read(const error_code & err, size_t bytes)
    {
        if ( err) stop();
        if ( !started() ) return;
        // process the msg
        std::string msg(read_buffer_, bytes);
        if ( msg.find("login ") == 0) on_login();
        //else if ( msg.find("ping") == 0) on_ping(msg);
        else if ( msg.find("clients ") == 0) on_clients(msg);
        else std::cerr << "invalid msg " << msg << std::endl;
    }

    void on_login()
    {
        std::cout << username_ << " logged in" << std::endl;
        do_ask_clients();
    }

    void on_ping(const std::string & msg)
    {
        std::istringstream in(msg);
        std::string answer;
        in >> answer >> answer;
        if ( answer == "client_list_changed") do_ask_clients();
        else postpone_ping();
    }

    void on_clients(const std::string & msg)
    {
        std::string clients = msg.substr(8);
        std::cout << username_ << ", new client list:" << clients ;
        postpone_ping();
    }

    void do_ping()
    {
        do_write("ping\n");
    }

    void postpone_ping()
    {
        // note: even though the server wants a ping every 5 secs, we randomly
        // don't ping that fast - so that the server will randomly disconnect us
        int millis = rand() % 7000;
        //std::cout << username_ << " postponing ping " << millis
        //          << " millis" << std::endl;
        timer_.expires_from_now(boost::posix_time::millisec(millis));
        timer_.async_wait( MEM_FN(do_ask_clients));
    }

    void do_ask_clients()
    {
        do_write("ask_clients\n");
    }

    void on_write(const error_code & err, size_t bytes)
    {
        do_read();
    }

    void do_read()
    {
        async_read(sock_, buffer(read_buffer_),
                   MEM_FN2(read_complete,_1,_2), MEM_FN2(on_read,_1,_2));
    }

    void do_write(const std::string & msg)
    {
        if ( !started() ) return;
        std::copy(msg.begin(), msg.end(), write_buffer_);
        sock_.async_write_some( buffer(write_buffer_, msg.size()),
                                MEM_FN2(on_write,_1,_2));
    }

    size_t read_complete(const boost::system::error_code & err, size_t bytes)
    {
        if ( err) return 0;
        bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n') < read_buffer_ + bytes;
        // we read one-by-one until we get to enter, no buffering
        return found ? 0 : 1;
    }

private:
    ip::tcp::socket sock_;
    enum { max_msg = 1024 };
    char read_buffer_[max_msg];
    char write_buffer_[max_msg];
    bool started_;
    std::string username_;
    deadline_timer timer_;
};

int main(int argc, char* argv[])
{
    // connect
    ip::tcp::endpoint ep( ip::address::from_string("127.0.0.1"), 8001);
    char* name = "John";

    talk_to_svr::start(ep, name);
    boost::this_thread::sleep( boost::posix_time::millisec(100));

    service.run();
}

*/
//
// chat_client.cpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2015 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <deque>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>

#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "../../chat_message.hpp"

using boost::asio::ip::tcp;

#define MEM_FN(x)       boost::bind(&self_type::x, shared_from_this())
#define MEM_FN1(x,y)    boost::bind(&self_type::x, shared_from_this(),y)
#define MEM_FN2(x,y,z)  boost::bind(&self_type::x, shared_from_this(),y,z)

// sock_.async_connect(ep, MEM_FN1(on_connect,_1));
// equivalent to
// sock_.async_connect(ep, boost::bind(&talk_to_svr::on_connect,shared_ptr_from_this(),_1));

/*
 * создаем завершающий обработчик async_connect,
 * он будет сохранять shared pointer на экземпляр chat_client
 * пока он не вызовет завершающий обработчик, тем самым, убедившись,
 * что мы все еще живы, когда это произойдет.
*/

typedef std::deque<chat_message> chat_message_queue;

class chat_client: public boost::enable_shared_from_this<chat_client>, boost::noncopyable
{
    typedef chat_client self_type;
public:

    typedef boost::system::error_code error_code;

    chat_client(boost::asio::io_service& io_service,
                tcp::resolver::iterator endpoint_iterator,
                const std::string & username) :io_service_(io_service), socket_(io_service), username_(username)
    {
        printf("chat_client : init\n");
        do_connect(endpoint_iterator);
    }

    void write(const chat_message& msg)
    {
        io_service_.post([this, msg]()
        {
            printf("chat_client : write\n");
            bool write_in_progress = !write_msgs_.empty();
            write_msgs_.push_back(msg);
            if (!write_in_progress)
            {
                do_write();
            }
        });
    }

    void close()
    {
        printf("chat_client : close\n");
        io_service_.post([this]() { socket_.close(); });
    }

private:
    void do_connect(tcp::resolver::iterator endpoint_iterator)
    {
        boost::asio::async_connect(socket_, endpoint_iterator, [this](boost::system::error_code ec, tcp::resolver::iterator)
        {
            printf("chat_client : do_connect\n");
            if ( !ec)
            {
                //write - "login " + username_ + "\n"
                username_.append("\n");
                chat_message msg;

                std::memcpy(msg.body(), "login :", 7);
                msg.body_length(username_.length()+7);

                std::memcpy(msg.body()+7, username_.c_str(), msg.body_length());
                msg.encode_header();

                write(msg);

                do_read_header();
            }
        });
    }

    void do_read_header()
    {
        boost::asio::async_read(socket_, boost::asio::buffer(read_msg_.data(), chat_message::header_length),
                                [this](boost::system::error_code ec, std::size_t)
        {
            printf("chat_client : do_read_header\n");
            if (!ec && read_msg_.decode_header())
            {
                do_read_body();
            }
            else
            {
                socket_.close();
            }
        });
    }

    void do_read_body()
    {
        boost::asio::async_read(socket_, boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
                                [this](boost::system::error_code ec, std::size_t)
        {
            printf("chat_client : do_read_body\n");
            if (!ec)
            {
                std::cout.write(read_msg_.body(), read_msg_.body_length());
                //std::cout << "\n";
                do_read_header();
            }
            else
            {
                socket_.close();
            }
        });
    }

    void do_write()
    {
        boost::asio::async_write(socket_, boost::asio::buffer(write_msgs_.front().data(), write_msgs_.front().length()),
                                [this](boost::system::error_code ec, std::size_t)
        {
            printf("chat_client : do_write\n");
            if (!ec)
            {
                //write_buffer_[0] = '\0';    // !!! clear write_buffer after sending to server
                write_msgs_.pop_front();
                if (!write_msgs_.empty())
                {
                    do_write();
                }
            }
            else
            {
                socket_.close();
            }
        });
    }
//===========================================================================
/*
    // interface for dialogue with the server
    void write_to_server(const std::string & msg)
    {
        printf("chat_client : write_to_server\n");
        std::copy(msg.begin(), msg.end(), write_buffer_);
        do_write();
    }

    void on_write_to_server(const error_code & err, size_t bytes)
    {
        do_read_to_server();
    }

    void do_read_to_server()
    {
        printf("chat_client : do_read_to_server\n");
        async_read(socket_, boost::asio::buffer(read_buffer_),
                   MEM_FN2(read_complete_to_server,_1,_2), MEM_FN2(on_read_to_server,_1,_2));
    }

    void on_read_to_server(const error_code & err, size_t bytes)
    {
        printf("chat_client : on_read_to_server\n");
        // process the msg
        std::string msg(read_buffer_, bytes);
        if ( msg.find("login ") == 0) int a;//on_login();
        //else if ( msg.find("ping") == 0) on_ping(msg);
        else if ( msg.find("clients ") == 0)int a;// on_clients(msg);
        else std::cerr << "invalid msg " << msg << std::endl;
    }

    size_t read_complete_to_server(const boost::system::error_code & err, size_t bytes)
    {
        if ( err) return 0;
        bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n') < read_buffer_ + bytes;
        // we read one-by-one until we get to enter, no buffering
        return found ? 0 : 1;
    }
*/
private:
    boost::asio::io_service& io_service_;
    tcp::socket socket_;
    chat_message read_msg_;
    chat_message_queue write_msgs_;
    std::string username_;
// interface to talk to server
    //ip::tcp::socket sock_;
    enum { max_msg = 1024 };
    char read_buffer_[max_msg];
    char write_buffer_[max_msg];
    bool started_;
};

int main(int argc, char* argv[])
{
    try
    {

        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", "8001");
        auto endpoint_iterator = resolver.resolve(query);
        chat_client c(io_service, endpoint_iterator, argv[1]);

        std::thread t([&io_service](){ io_service.run(); });

        char line[chat_message::max_body_length + 1];
        while (std::cin.getline(line, chat_message::max_body_length + 1))
        {
            chat_message msg;
            msg.body_length(std::strlen(line));
            std::memcpy(msg.body(), line, msg.body_length());
            msg.encode_header();
            c.write(msg);
        }

        c.close();
        t.join();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}

