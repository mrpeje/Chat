#include "Client.hpp"


void chat_client::write(const chat_message& msg)
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

void chat_client::close()
{
    printf("chat_client : close\n");
    io_service_.post([this]() { socket_.close(); });
}

bool chat_client::findUser(std::string searchingUser)
{
    for(auto user: listOfClients_)
    {
        if(strcmp(user.c_str(), searchingUser.c_str()) == 0)
            return true;
    }
    return false;
}

void chat_client::do_connect(tcp::resolver::iterator endpoint_iterator)
{
    boost::asio::async_connect(socket_, endpoint_iterator, [this](boost::system::error_code ec, tcp::resolver::iterator)
    {
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

void chat_client::do_read_header()
{
    boost::asio::async_read(socket_, boost::asio::buffer(read_msg_.data(), chat_message::header_length),
                            [this](boost::system::error_code ec, std::size_t)
    {
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

void chat_client::do_read_body()
{
    boost::asio::async_read(socket_, boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
                            [this](boost::system::error_code ec, std::size_t)
    {
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
        else if(!ec && read_msg_.getSrvMsg() == ServiceMsg::toClient)
        {
            Crypto crypto;


            char *b64ek, *b64iv, *b64Msg;
            int b64_ek_Length, b64_iv_Length, b64_Msg_Length, decMsgLen;
            char *decMsg = NULL;

            //pars body

            string msg(read_msg_.body());
            smatch match;
            std::regex rx("[|]");
            if (regex_search(msg, match, rx));
                msg = match.suffix().str();
            regex delimt("(\\|)?");

            //decode ek, iv and msg from b64 view
            unsigned char * ek ;
            int ekl = base64Decode(b64ek, b64_ek_Length, &ek);
            unsigned char * iv ;
            int ivl = base64Decode(b64iv, b64_iv_Length, &iv);
            unsigned char * encMessage ;
            int msg_Length = base64Decode(b64Msg, b64_Msg_Length, &encMessage);

            //decode msg
            if((decMsgLen = crypto.rsaDecrypt(encMessage, (size_t)msg_Length,
                                              ek, ekl, iv, ivl,
                                              (unsigned char**)&decMsg)) == -1)
            {
                fprintf(stderr, "Decryption failed\n");
                return 1;
            }

        }
        if (!ec)
        {
            std::cout<< "DEBUG in ["<<read_msg_.data()<<"]\n";    // issue #4
            read_msg_.Clear();
            do_read_header();
        }
        else
        {

            socket_.close();
        }
    });
}

void chat_client::do_write()
{
    boost::asio::async_write(socket_, boost::asio::buffer(write_msgs_.front().data(), write_msgs_.front().length()),
                            [this](boost::system::error_code ec, std::size_t)
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
        else
        {
            socket_.close();
        }
    });
}

bool chat_client::generate_key()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;


    int             bits = 2048;
    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}
int chat_client::genKey()
{
    int rc;

    RSA_ptr rsa(RSA_new(), ::RSA_free);
    BN_ptr bn(BN_new(), ::BN_free);

    BIO_FILE_ptr pem1(BIO_new_file("rsa-public-1.pem", "w"), ::BIO_free);
    BIO_FILE_ptr pem2(BIO_new_file("rsa-private-1.pem", "w"), ::BIO_free);

    rc = BN_set_word(bn.get(), RSA_F4);
    ASSERT(rc == 1);

    // Generate key
    rc = RSA_generate_key_ex(rsa.get(), 2048, bn.get(), NULL);
    ASSERT(rc == 1);

    // Convert RSA to PKEY
    EVP_KEY_ptr pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
    rc = EVP_PKEY_set1_RSA(pkey.get(), rsa.get());
    ASSERT(rc == 1);


    // Write public key in PKCS PEM
    rc = PEM_write_bio_PUBKEY(pem1.get(), pkey.get());
    //rc = PEM_write_bio_RSAPublicKey(pem1.get(), rsa.get());
    ASSERT(rc == 1);

    // Write private key in PKCS PEM.
    rc = PEM_write_bio_PKCS8PrivateKey(pem2.get(), pkey.get(), NULL, NULL, 0, NULL, NULL);
    ASSERT(rc == 1);

    return 0;
}

int chat_client::do_evp_unseal(FILE *rsa_private_key_file, const char *line, char *decryptedLine)
{
    int retval = 0;

    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[4096];
    unsigned char buffer_out[4096 + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out;
    unsigned char *ek;
    unsigned int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (!PEM_read_RSAPrivateKey (rsa_private_key_file, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Private Key File.\n");
        ERR_print_errors_fp(stderr);
        retval = 2;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 3;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey));

    /* First need to fetch the encrypted key length, encrypted key and IV */
    memcpy ( &eklen_n, line, sizeof eklen_n);
//    if (fread(&eklen_n, sizeof eklen_n, 1, in_file) != 1)
//    {
//        perror("input file");
//        retval = 4;
//        goto out_free;
//    }
    eklen = ntohl(eklen_n);
    if (eklen > (uint32_t)EVP_PKEY_size(pkey))
    {
        fprintf(stderr, "Bad encrypted key length (%u > %d)\n", eklen,
            EVP_PKEY_size(pkey));
        retval = 4;
        goto out_free;
    }

    memcpy ( ek, line, eklen);

//    if (fread(ek, eklen, 1, in_file) != 1)
//    {
//        perror("input file");
//        retval = 4;
//        goto out_free;
//    }
    memcpy ( iv, line, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
//    if (fread(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()), 1, in_file) != 1)
//    {
//        perror("input file");
//        retval = 4;
//        goto out_free;
//    }

    if (!EVP_OpenInit(&ctx, EVP_aes_128_cbc(), ek, eklen, iv, pkey))
    {
        fprintf(stderr, "EVP_OpenInit: failed.\n");
        retval = 3;
        goto out_free;
    }

//    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
//    {
        if (!EVP_OpenUpdate(&ctx, buffer_out, &len_out, buffer, strlen(line)))
        {
            fprintf(stderr, "EVP_OpenUpdate: failed.\n");
            retval = 3;
            goto out_free;
        }

//        if (fwrite(buffer_out, len_out, 1, out_file) != 1)
//        {
//            perror("output file");
//            retval = 5;
//            goto out_free;
//        }
//    }

//    if (ferror(in_file))
//    {
//        perror("input file");
//        retval = 4;
//        goto out_free;
//    }

    if (!EVP_OpenFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_OpenFinal: failed.\n");
        retval = 3;
        goto out_free;
    }

    memcpy(decryptedLine, buffer_out, len_out);
//    if (fwrite(buffer_out, len_out, 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }

    out_free:
    EVP_PKEY_free(pkey);
    free(ek);

    out:
    return retval;
}

int chat_client::do_evp_seal(FILE *rsa_public_key_file, const char *line, char *encryptedLine)
{
    string str1;
    int retval = 0;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[chat_message::max_body_length - EVP_MAX_IV_LENGTH + 1];
    unsigned char buffer_out[chat_message::max_body_length + 1];

    int len_out;
    unsigned char *ek;
    int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    FILE *pub = fopen("public.pem","r");

    if(!pub){
        printf("Error: open public.pem\n");
        return 0;
    }

    int offset;
    int len = strlen(line);
    if (!/*PEM_read_RSA_PUBKEY*/PEM_read_RSAPublicKey(/*rsa_public_key_file*/pub, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Public Key File.\n");
        ERR_print_errors_fp(stderr);
        retval = 2;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 3;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey)*sizeof(int));

    if (!EVP_SealInit(&ctx, EVP_aes_128_cbc(), &ek, &eklen, iv, &pkey, 1))
    {
        fprintf(stderr, "EVP_SealInit: failed.\n");
        retval = 3;
        goto out_free;
    }

    /* First we write out the encrypted key length, then the encrypted key,
     * then the iv (the IV length is fixed by the cipher we have chosen).
     */

    eklen_n = htonl(eklen);
    //char * intStr = itoa(eklen);
    str1 = to_string(eklen);
    strcpy(encryptedLine, str1.c_str());
    offset = str1.length();
    //memcpy(encryptedLine, &eklen_n, sizeof(eklen_n));
//    if (fwrite(&eklen_n, sizeof eklen_n, 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }
    memcpy(encryptedLine + offset, ek, eklen);
    offset = eklen;
//    if (fwrite(ek, eklen, 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }
    memcpy(encryptedLine + offset, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    offset = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
//    if (fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()), 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }

    /* Now we process the input file and write the encrypted data to the
         * output file. */


    //while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)


    if (!EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len)) // !!!!!
    {
        fprintf(stderr, "EVP_SealUpdate: failed.\n");
        retval = 3;
        goto out_free;
    }

    memcpy(encryptedLine + offset, buffer_out, len_out);
    offset = len_out;
//    if (fwrite(buffer_out, len_out, 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }


//    if (ferror(in_file))
//    {
//        perror("input file");
//        retval = 4;
//        goto out_free;
//    }

    if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        retval = 3;
        goto out_free;
    }

    memcpy(encryptedLine + offset, buffer_out, len_out);
//    if (fwrite(buffer_out, len_out, 1, out_file) != 1)
//    {
//        perror("output file");
//        retval = 5;
//        goto out_free;
//    }

    out_free:
    EVP_PKEY_free(pkey);
    free(ek);

    out:
    return retval;
}








