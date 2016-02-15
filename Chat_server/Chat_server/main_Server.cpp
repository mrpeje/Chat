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
typedef std::shared_ptr<chat_room> chat_room_ptr;

void EraseClient(std::string user);
int FindEmptyRoom();
int FindRoom(chat_participant_ptr a);
client_ptr FindClient(std::string user);


typedef std::vector<client_ptr> client_array;
client_array Clients;

// Issue #2
typedef std::vector<chat_room_ptr> room_array;
room_array Rooms;


//----------------------------------------------------------------------

class chat_participant
{
public:
    virtual ~chat_participant() {}
    virtual void deliver(const chat_message& msg) = 0;
};

//----------------------------------------------------------------------

class chat_room : public std::enable_shared_from_this<chat_room>
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
    // Issue #6
    void disconnectAllUsers(chat_participant_ptr participant)
    {
        printf("chat_room : disconnectAllUsers\n");
        this->leave(participant);

        chat_message msg;
        std::string line = "User leave chat room";
        msg.body_length(line.length());
        std::memcpy(msg.body(), line.c_str(), msg.body_length());
        msg.encode_header();

        this->deliver(msg);

        for (auto participant: participants_)
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

    bool isEmpty()
    {
        return this->participants_.empty();
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
    }

    void start()
    {
        participant_ = shared_from_this();
        serviceRoom_.get()->join(shared_from_this());
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
            if (!ec && read_msg_.decode_header())
            {
                do_read_body();
            }
            else        // Issue #6 Correct deleting user if error
            {
                int roomIndx = -1;
                roomIndx = FindRoom(participant_);

                if(roomIndx != -1)
                {
                    Rooms[roomIndx].get()->disconnectAllUsers(participant_);
                }
                serviceRoom_.get()->leave(participant_);
                EraseClient(username());

                on_Clients();
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
            std::cout<< "DEBUG in ["<<read_msg_.data()<<"]\n";    // issue #4

            if(read_msg_.getSrvMsg() == ServiceMsg::onLogin)
            {
                std::istringstream in(read_msg_.body());
                in >> username_;
                std::cout<<username_<< "\n";
                Clients.push_back( shared_from_this());
                on_Clients();
            }
            else if(read_msg_.getSrvMsg() == ServiceMsg::toClient)
            {
                  const int roomIndx = FindRoom(participant_);

                  if(roomIndx != -1)
                  {
                     Rooms[roomIndx].get()->deliver(read_msg_);
                  }

            }
            else if(read_msg_.getSrvMsg() == ServiceMsg::JoinUsers)
            {
                const std::string name(read_msg_.body());
                // Add: if client alredy join to another client
                const client_ptr ptr = FindClient(name);
                if(ptr)
                {
                    const int emptyRoom = FindEmptyRoom();
                    Rooms[emptyRoom].get()->join(shared_from_this());
                    Rooms[emptyRoom].get()->join(ptr);
                }
                //else !!!!!

            }
            else if(read_msg_.getSrvMsg() == ServiceMsg::DisconnectUser)
            {
                const int roomIndx = FindRoom(participant_);

                if(roomIndx != -1)
                {
                    Rooms[roomIndx].get()->disconnectAllUsers(participant_);
                }
            }
            read_msg_.Clear();
            if (!ec)
            {
                do_read_header();
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
            if (!ec)
            {
                std::cout<< "DEBUG out["<<write_msgs_.front().data()<<"]\n";    // issue #4
                write_msgs_.pop_front();
                if (!write_msgs_.empty())
                {
                    do_write();
                }
            }
            else        // Issue #6 Correct deleting user if error
            {         
                const int roomIndx = FindRoom(participant_);

                if(roomIndx != -1)
                {
                    Rooms[roomIndx].get()->disconnectAllUsers(participant_);
                }
                serviceRoom_.get()->leave(participant_);
                EraseClient(username());
            }
        });
    }

    void on_Clients()
    {
        std::string array_of_Clients;
        chat_message msg;

        msg.setSrvMsg(ServiceMsg::listOfClients);

        // Copy usernames of Clients to string
        for( client_array::const_iterator it = Clients.begin(), end = Clients.end() ; it != end; ++it)
            array_of_Clients += (*it)->username() + " ";

        array_of_Clients[array_of_Clients.length()-1] = '\n';

        msg.body_length(array_of_Clients.length());

        std::memcpy(msg.body(), array_of_Clients.c_str(), msg.body_length());
        msg.encode_header();

        serviceRoom_.get()->deliver(msg);
    }

    std::string username_;
    chat_participant_ptr participant_;
    tcp::socket socket_;
    chat_room_ptr serviceRoom_;            // room for dilivering service messages
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
        // Add ServiceRoom
        Rooms.push_back(std::make_shared<chat_room>(room_));
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
                std::make_shared<chat_session>(std::move(socket_))->start();
            }
            do_accept();
        });
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
    chat_room_ptr room_ptr_;
    chat_room room_;
};

// Looking for user in Clients array by his name
client_ptr FindClient(const std::string user)
{
    for( client_array::iterator it = Clients.begin(), end = Clients.end(); it != end; ++it)
    {
        if((*it)->username() == user)
        {
            return (*it);
        }
    }
    return NULL;
}

// erase client from the list of Clients
void EraseClient(std::string user)
{
    for( client_array::iterator it = Clients.begin(), end = Clients.end(); it != end; ++it)
    {
        if((*it)->username() == user)
        {
            Clients.erase(it);
            return;
        }

    }
}

// Looking for user in Rooms and return room's index if that user connected to that room.
int FindRoom(chat_participant_ptr ptr)
{
    int rezIndx = 1;

    auto it = Rooms.begin();
    // Start searching from second room, first room is a ServiceRoom
    for (it++; it != Rooms.end(); ++it)
    {
        for (auto participant: (*it).get()->getParticipants())
        {
            if(participant == ptr)
            {
               return rezIndx;
            }
        }
        rezIndx++;
    }
    return -1;
}

// Looking for empty room
int FindEmptyRoom()
{
    int rezIndx = 1;

    auto it = Rooms.begin();
    // Start searching from second room, first room is a ServiceRoom
    for (it++; it != Rooms.end(); ++it)
    {
        if((*it).get()->isEmpty())
            return rezIndx;
        rezIndx++;
    }

    // If no empty rooms create new one
    chat_room newRoom;
    Rooms.push_back(std::make_shared<chat_room>(newRoom));

    return Rooms.size()-1;
}

//----------------------------------------------------------------------

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 1)
        {
            std::cerr << "Usage: chat_server\n";
            return 1;
        }

        boost::asio::io_service io_service;
        tcp::endpoint endpoint(tcp::v4(), 8001);

        chat_server server(io_service, endpoint);

        io_service.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}

