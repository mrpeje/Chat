//
// chat_message.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2015 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef CHAT_MESSAGE_HPP
#define CHAT_MESSAGE_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Issue #1
enum class ServiceMsg
{
    onLogin = 0,
    toClient = 1,
    listOfClients = 2,
    JoinUsers = 3,          // Connect user to room
    DisconnectUser = 4      // Disconnect user from room
};

class chat_message
{
public:
    enum { header_length = 5 };
    enum { max_body_length = 1024 };

	chat_message()
    : body_length_(0),
      srvMsg_(ServiceMsg::toClient)
	{
	}

    void Clear()
    {
        memset(data_,0,strlen(data_));
    }

	const char* data() const
	{
		return data_;
	}

	char* data()
	{
		return data_;
	}

	std::size_t length() const
	{
		return header_length + body_length_;
	}

	const char* body() const
	{
		return data_ + header_length;
	}

	char* body()
	{

		return data_ + header_length;
	}

	std::size_t body_length() const
	{
		return body_length_;
	}

	void body_length(std::size_t new_length)
	{
		body_length_ = new_length;
		if (body_length_ > max_body_length)
			body_length_ = max_body_length;
	}

    void setSrvMsg(ServiceMsg m)
    {
        srvMsg_ = m;
    }

    ServiceMsg getSrvMsg()
    {
        return srvMsg_;
    }

	bool decode_header()
	{
		char header[header_length + 1] = "";
		std::strncat(header, data_, header_length);

        // Issue #1
        char srvMsg[2] = "";
        std::strncat(srvMsg, header, 1);

        srvMsg_ = static_cast<ServiceMsg>(std::atoi(srvMsg));

        body_length_ = std::atoi(header+1);

		if (body_length_ > max_body_length)
		{
			body_length_ = 0;
			return false;
		}
		return true;
	}

	void encode_header()
	{
		char header[header_length + 1] = "";
        std::sprintf(header, "%1d", static_cast<int>(srvMsg_));			// Issue #1

        std::sprintf(header+1, "%4d", static_cast<int>(body_length_));
		std::memcpy(data_, header, header_length);
	}

private:
	char data_[header_length + max_body_length];
	std::size_t body_length_;
    ServiceMsg srvMsg_;									// Issue #1

};

#endif // CHAT_MESSAGE_HPP
