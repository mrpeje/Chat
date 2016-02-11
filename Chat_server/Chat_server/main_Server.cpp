#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "../../chat_message.hpp"

using boost::asio::ip::tcp;

//----------------------------------------------------------------------

typedef std::deque<chat_message> chat_message_queue;

class chat_room;
class chat_participant;
class chat_session;

typedef std::shared_ptr<chat_participant> chat_participant_ptr;
typedef std::shared_ptr<chat_session> client_ptr;
typedef std::vector<client_ptr> array;

int FindRoom(chat_participant_ptr a);
client_ptr FindClient(std::string user);

array clients;
// Issue #2
std::vector <chat_room> Rooms;

int NextEmptyRoom;

//----------------------------------------------------------------------

class chat_participant
{
public:
    virtual ~chat_participant() {}
    virtual void deliver(const chat_message& msg) = 0;
};

//----------------------------------------------------------------------

class chat_room
{
public:
    void join(chat_participant_ptr participant)
    {
        printf("chat_room : join\n");
        participants_.insert(participant);
    }

    void leave(chat_participant_ptr participant)
    {
        printf("chat_room : leave\n");
        participants_.erase(participant);
    }

    void deliver(const chat_message& msg)
    {
        printf("chat_room : deliver\n");
        recent_msgs_.push_back(msg);
        while (recent_msgs_.size() > max_recent_msgs)
            recent_msgs_.pop_front();

        for (auto participant: participants_)
        participant->deliver(msg);
    }
    inline const std::set<chat_participant_ptr> getParticipants()
    {
        return participants_;
    }
private:
    std::set<chat_participant_ptr> participants_;
    enum { max_recent_msgs = 100 };
    chat_message_queue recent_msgs_;
};

//----------------------------------------------------------------------

class chat_session: public chat_participant, public std::enable_shared_from_this<chat_session>
{
public:
    inline const std::string username() const { return username_; }

    typedef chat_session self_type;
    chat_session(tcp::socket socket)
    : socket_(std::move(socket)),
    serviceRoom_(Rooms.front())
    {
        printf("chat_session : init\n");
    }

    void start()
    {
        printf("chat_session : start\n");
        participant_ = shared_from_this();
        serviceRoom_.join(shared_from_this());
        do_read_header();
    }

    void deliver(const chat_message& msg)
    {
        printf("chat_session : deliver\n");
        bool write_in_progress = !write_msgs_.empty();
        write_msgs_.push_back(msg);
        if (!write_in_progress)
        {
            do_write();
        }
    }

private:
    void do_read_header()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(read_msg_.data(), chat_message::header_length),
                                    [this, self](boost::system::error_code ec, std::size_t)
        {
            printf("chat_session : do_read_header\n");
            if (!ec && read_msg_.decode_header())
            {
                do_read_body();
            }
            else
            {
                serviceRoom_.leave(shared_from_this());
            }
        });
    }

    void do_read_body()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_,
        boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
                            [this, self](boost::system::error_code ec, std::size_t)
        {
            printf("chat_session : do_read_body\n");

            std::cout<< "DEBUG in ["<<read_msg_.data()<<"]\n";    // issue #4

            if(read_msg_.getSrvMsg() == ServiceMsg::onLogin)
            {
                std::istringstream in(read_msg_.body());
                in >> username_;
                std::cout<<username_<< "\n";
                clients.push_back( shared_from_this());
                on_clients();
            }
            else if(read_msg_.getSrvMsg() == ServiceMsg::toClient)
            {
                  int roomIndx = -1;
                  roomIndx = FindRoom(participant_);

                  if(roomIndx != -1)
                  {
                     Rooms[roomIndx].deliver(read_msg_);
                  }

            }
            else if(read_msg_.getSrvMsg() == ServiceMsg::JoinUsers)
            {
                std::string name(read_msg_.body());

                const client_ptr ptr = FindClient(name);
                if(ptr)
                {
                    Rooms[NextEmptyRoom].join(shared_from_this());
                    Rooms[NextEmptyRoom].join(ptr);
                    NextEmptyRoom++;
                }
                //else !!!!!

            }
            if (!ec)
            {
                do_read_header();
            }
            else
            {
                serviceRoom_.leave(shared_from_this());
            }
        });
    }

    void do_write()
    {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
                                boost::asio::buffer(write_msgs_.front().data(),
                                write_msgs_.front().length()),
        [this, self](boost::system::error_code ec, std::size_t)
        {
            printf("chat_session : do_write\n");
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
                serviceRoom_.leave(shared_from_this());
            }
        });
    }

    void on_clients()
    {
        std::string array_of_clients;
        chat_message msg;

        msg.setSrvMsg(ServiceMsg::listOfClients);

        // Copy usernames of clients to string
        for( array::const_iterator b = clients.begin(), e = clients.end() ; b != e; ++b)
            array_of_clients += (*b)->username() + " ";

        array_of_clients[array_of_clients.length()-1] = '\n';

        msg.body_length(array_of_clients.length());

        std::memcpy(msg.body(), array_of_clients.c_str(), msg.body_length());
        msg.encode_header();

        serviceRoom_.deliver(msg);
    }

    std::string username_;
    chat_participant_ptr participant_;
    tcp::socket socket_;
    chat_room& serviceRoom_;            // room for dilivering service messages
    chat_message read_msg_;
    chat_message_queue write_msgs_;
};

//----------------------------------------------------------------------

class chat_server
{
public:

    chat_server(boost::asio::io_service& io_service,
                const tcp::endpoint& endpoint)
                : acceptor_(io_service, endpoint),
    socket_(io_service)
    {
        NextEmptyRoom = 1;
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(socket_,
                                [this](boost::system::error_code ec)
        {
            if (!ec)
            {
                chat_room newRoom;          // Create new empty room when new client accepted
                Rooms.push_back(newRoom);

                std::make_shared<chat_session>(std::move(socket_))->start();
            }
            do_accept();
        });
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
};

// Looking for user in clients array by his name
client_ptr FindClient(std::string user)
{
    for( array::iterator b = clients.begin(), e = clients.end(); b != e; ++b)
    {
        if((*b)->username() == user)
        {
            return (*b);
        }

    }
    return NULL;
}

// Looking for user in Rooms and return room's index if that user connected to that room.
int FindRoom(chat_participant_ptr a)
{
    int rezIndx;

    auto it = Rooms.begin();

    for (it++; it != Rooms.end(); ++it)
    {
        for (auto participant: (*it).getParticipants())
        {
            if(participant == a)
            {
               return rezIndx;
            }
        }
        rezIndx++;
    }
    return -1;
}


//----------------------------------------------------------------------

int main(int argc, char* argv[])
{
    try
    {

        boost::asio::io_service io_service;

        std::list<chat_server> servers;

        tcp::endpoint endpoint(tcp::v4(), 8001);
        servers.emplace_back(io_service, endpoint);

        io_service.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}

