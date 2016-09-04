#ifndef CLIENT_H
#define CLIENT_H

#include "base64.hpp"
#include "Crypto.hpp"

#include <regex>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#include <arpa/inet.h> /* For htonl() */
using namespace std;
using std::unique_ptr;

#include <cassert>
#define ASSERT assert

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

#include "../../chat_message.hpp"

using boost::asio::ip::tcp;

typedef std::deque<chat_message> chat_message_queue;

class chat_client: public boost::enable_shared_from_this<chat_client>, boost::noncopyable
{
    typedef chat_client self_type;
public:

    typedef boost::system::error_code error_code;

//    ~chat_client()
//    {

//    }

    chat_client(boost::asio::io_service& io_service,
                tcp::resolver::iterator endpoint_iterator,
                const std::string & username)
                :io_service_(io_service),
                 socket_(io_service),
                 username_(username),
                 bp_public (NULL),
                 bp_private(NULL)
    {
        bool ret = generate_key();
        do_connect(endpoint_iterator);
    }

    void write(const chat_message& msg);

    void close();
    bool findUser(std::string searchingUser);

    int do_evp_unseal(FILE *rsa_private_key_file,
                      const char *line,
                      char *encryptedLine);

    int do_evp_seal(  FILE *rsa_public_key_file,
                      const char *line,
                      char *encryptedLine);
private:
    void do_connect(tcp::resolver::iterator endpoint_iterator);
    void do_read_header();
    void do_read_body();
    void do_write();

    int genKey();
    bool generate_key();



private:
    boost::asio::io_service& io_service_;
    tcp::socket socket_;
    chat_message read_msg_;
    chat_message_queue write_msgs_;
    std::string username_;
    BIO *bp_public, *bp_private;
    std::vector<std::string> listOfClients_;
};
#endif // CLIENT_H

