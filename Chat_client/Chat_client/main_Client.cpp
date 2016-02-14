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
                const std::string & username)
                :io_service_(io_service),
                 socket_(io_service),
                 username_(username)
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

    bool findUser(std::string searchingUser)
    {
        for(auto user: listOfClients_)
        {
            if(strcmp(user.c_str(), searchingUser.c_str()) == 0)
                return true;
        }
        return false;
    }

private:
    void do_connect(tcp::resolver::iterator endpoint_iterator)
    {
        boost::asio::async_connect(socket_, endpoint_iterator, [this](boost::system::error_code ec, tcp::resolver::iterator)
        {
            printf("chat_client : do_connect\n");
            if ( !ec)
            {
                chat_message msg;

                msg.setSrvMsg(ServiceMsg::onLogin);
                msg.body_length(username_.length()+1);

                std::memcpy(msg.body(), username_.c_str(), msg.body_length());
                std::memcpy(msg.body()+msg.body_length(), "\n", 1);
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
            // Issue #3
            if(!ec && read_msg_.getSrvMsg() == ServiceMsg::listOfClients)
            {
                std::stringstream ss(read_msg_.body());
                std::string buf;

                while (ss >> buf)
                {
                    if(username_ != buf)
                        listOfClients_.push_back(buf);
                }

            }
            if (!ec)
            {
                std::cout<< "DEBUG in ["<<read_msg_.data()<<"]\n";    // issue #4
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
                std::cout<< "DEBUG out["<<write_msgs_.front().data()<<"]\n";    // issue #4
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



private:
    boost::asio::io_service& io_service_;
    tcp::socket socket_;
    chat_message read_msg_;
    chat_message_queue write_msgs_;
    std::string username_;
    std::vector<std::string> listOfClients_;
};



int main(int argc, char* argv[])
{
    try
    {
        std::string srvMsg1 = "|connect to ";
        std::string srvMsg2 = "|disconnect";

        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", "8001");
        auto endpoint_iterator = resolver.resolve(query);
        chat_client c(io_service, endpoint_iterator, argv[1]);

        std::thread t([&io_service](){ io_service.run(); });

        char line[chat_message::max_body_length + 1];
        while (std::cin.getline(line, chat_message::max_body_length + 1))
        {
            bool permissionToSend = true;
            chat_message msg;
            msg.setSrvMsg(ServiceMsg::toClient);
            msg.body_length(std::strlen(line));

            std::memcpy(msg.body(), line, msg.body_length());

            // Issue #2
            if(strstr(msg.body(),srvMsg1.c_str()))
            {
                msg.body_length(std::strlen(line) - srvMsg1.length());
                msg.setSrvMsg(ServiceMsg::JoinUsers);
                std::memcpy(msg.body(), line + srvMsg1.length(), msg.body_length());

            }
            // Issue #6
            else if(strstr(msg.body(),srvMsg2.c_str()))
            {
                msg.body_length(std::strlen(line) - srvMsg2.length());
                msg.setSrvMsg(ServiceMsg::DisconnectUser);
                std::memcpy(msg.body(), line + srvMsg2.length(), msg.body_length());
            }

            std::memcpy(msg.body()+msg.body_length(), "\n", msg.body_length()+1);
            msg.encode_header();

            // Сhecking for the name in the list of clients
            if(msg.getSrvMsg() == ServiceMsg::JoinUsers)
            {
                std::string userName(msg.body());
                userName[userName.length()-1] = '\0';       // Cut '\n' char
                permissionToSend = c.findUser(userName);
                std::cout << "cant find user\n";
            }

            if(permissionToSend)
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

