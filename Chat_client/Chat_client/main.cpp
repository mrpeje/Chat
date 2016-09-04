#include <thread>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "Client.hpp"



using namespace std;

int main(int argc, char* argv[])
{
    try
    {
        string srvMsg1 = "|connect to ";
        string srvMsg2 = "|disconnect";
        string login_name = "";

        if (argc > 3)
        {
            printf("Try -h or --help for print help\n");
            return 1;
        }


        const char* short_options = "n:h";
        static struct option logopts[] =
        {
            { "name", required_argument, 0 , 'n'},
            { "help", no_argument      , 0 , 'h'},
            { 0     , 0                , 0 , 0}
        };
        int opt = 0;

        while ((opt = getopt_long(argc, argv, short_options, logopts, NULL)) != -1)
        {
            if(opt != -1)
            {
                switch(opt)
                {
                    case 'n':
                    {
                        login_name = optarg;
                        printf("login as %s\n", login_name.c_str());
                        break;
                    }
                    case 'h':
                    {
                        printf("\nUsage: chat_client --name or -n <login Name>\n");
                        printf("Use commands \n");
                        printf("        '%s' - To connect to private chat room with UserName\n", srvMsg1.c_str());
                        printf("        '%s' - To disconnect from private room\n\n", srvMsg2.c_str());
                        return 0;
                    }
                    case '?': default:
                    {
                        printf("found unknown option\n");
                        printf("Try -h or --help for print help\n");
                        return 0;
                    }
                }
            }
        }

        if (optind < argc)
        {
            printf("non-option ARGV-elements: ");
            while (optind < argc)
                printf("%s ", argv[optind++]);
            printf("\n");
            return 0;
        }

        // init Crypto params
        Crypto crypto;

        string message;
        unsigned char *encMsg = NULL;
        char *decMsg          = NULL;
        int encMsgLen;
        int decMsgLen;

        unsigned char *ek;
        unsigned char *iv;
        size_t ekl = 0;
        size_t ivl = 0;
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", "8001");
        auto endpoint_iterator = resolver.resolve(query);
        chat_client c(io_service, endpoint_iterator, login_name);

        thread t([&io_service](){ io_service.run(); });

        char line[chat_message::max_body_length];

        //for testing
        while (1)
        //while (cin.getline(message, chat_message::max_body_length))
        {
            getline(cin, message);
            bool permissionToSend = true;

            chat_message msg;

            // Issue #2
            if(std::strstr(message.c_str(),srvMsg1.c_str()))
            {
                msg.setSrvMsg(ServiceMsg::JoinUsers);
                memcpy(msg.body(), message.c_str() + srvMsg1.length(), message.length());
                msg.body_length(message.length());

            }
            // Issue #6
            else if(strstr(msg.body(),srvMsg2.c_str()))
            {
                msg.setSrvMsg(ServiceMsg::DisconnectUser);
                memcpy(msg.body(), message.c_str() + srvMsg1.length(), message.length());
                msg.body_length(message.length());
            }
            else
            {
                msg.setSrvMsg(ServiceMsg::toClient);
                message.append("\n");
                // Encrypt the message with RSA
                // Note the +1 tacked on to the string length argument.
                // We want to encrypt the NUL terminator too. If we don't,
                // we would have to put it back after decryption, but it's easier to keep it with the string.
                if((encMsgLen = crypto.rsaEncrypt((const unsigned char*)message.c_str(),
                                                  message.size()+1, &encMsg,
                                                  &ek, &ekl, &iv, &ivl)) == -1)
                {
                    fprintf(stderr, "Encryption failed\n");
                    return 1;
                }
                message.clear();

                char* b64EK = base64Encode(ek, ekl);
                message.append(to_string(strlen(b64EK)).c_str());
                message.append("|");
                message.append(b64EK);

                char* b64IV = base64Encode(iv, ivl);
                message.append(to_string(strlen(b64IV)).c_str());
                message.append("|");
                message.append(b64IV);

                char* b64String = base64Encode(encMsg, encMsgLen);
                message.append(to_string(strlen(b64String)).c_str());
                message.append("|");
                message.append(b64String);


//                unsigned char * b64EKS ;
//                int b64EKF = base64Decode(b64EK, strlen(b64EK), &b64EKS);
//                unsigned char * b64IVS ;
//                int b64IVF = base64Decode(b64IV, strlen(b64IV), &b64IVS);


//                unsigned char * f ;
//                int F = base64Decode(b64String, strlen(b64String), &f);

//                if((decMsgLen = crypto.rsaDecrypt(f, (size_t)F,
//                                                  b64EKS, ekl, b64IVS, ivl,
//                                                  (unsigned char**)&decMsg)) == -1)
//                {
//                    fprintf(stderr, "Decryption failed\n");
//                    return 1;
//                }


//                char* b64StringF = base64Encode(f, F);
                msg.body_length(message.length());
                memcpy(msg.body(), message.c_str(), message.length());
            }

            memcpy(msg.body()+msg.body_length(), "\n", msg.body_length()+1);
            msg.encode_header();

            // Сhecking for the name in the list of clients
            if(msg.getSrvMsg() == ServiceMsg::JoinUsers)
            {
                string userName(msg.body());
                //userName[userName.length()-1] = '\0';       // Cut '\n' char
                permissionToSend = c.findUser(userName);
            }

            if(permissionToSend)
                c.write(msg);
            else
                cout << "can't find user\n";
        }

        c.close();
        t.join();
    }
    catch (exception& e)
    {
        cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
