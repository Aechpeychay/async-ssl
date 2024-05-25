//
// Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP
#define BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>

/*  Load a signed certificate into the ssl context, and configure
    the context for use with a server.

    For this to work with the browser or operating system, it is
    necessary to import the "Beast Test CA" certificate into
    the local certificate store, browser, or operating system
    depending on your environment Please see the documentation
    accompanying the Beast certificate for more details.
*/
inline
void
load_server_certificate(boost::asio::ssl::context& ctx)
{
    /*
        The certificate was generated from CMD.EXE on Windows 10 using:

        winpty openssl dhparam -out dh.pem 2048
        winpty openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "//C=US\ST=CA\L=Los Angeles\O=Beast\CN=www.example.com"
    */

    std::string const cert = 
"-----BEGIN CERTIFICATE-----\n"
"MIIC/TCCAeWgAwIBAgIUKUbYn2CyfyT1L4TWm0NM2i5gwD0wDQYJKoZIhvcNAQEL\n"
"BQAwDTELMAkGA1UEBhMCUlUwIBcNMjQwNTIzMjMyMjEyWhgPMjA3OTAyMjQyMzIy\n"
"MTJaMA0xCzAJBgNVBAYTAlJVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
"AQEAtnMDw5ZEGLkCiFPr+/O0/xuts4a69pncT0ugDkvDqdiJ3WpEtTU0DhK46Vb8\n"
"F5InZje46yPB/6ckxPqjLvl+cwXh3TwSRb9eNcqf5cBLGEL9WHaPgS9bxNzoYBYc\n"
"kWH9eGAdL7LjoPpQe3sn5NpxhGskGitOxjTtVnOIa9ISlAgB/mtJpgqihInONg5k\n"
"QcXQdbR2tvwWHK7cRQGXfxaMXBFdq1oe3hnWtZ43ZCGLZ/p3bbgzBWIREs4qXzyU\n"
"G46wRTRXRIip2LLdR6siHqGt7ES27JOFV8WUfnzRV0AMX0tM8dmfgiyUQNZHwlnr\n"
"w9lPGOz9woJTqZh8+eVANKpakwIDAQABo1MwUTAdBgNVHQ4EFgQUsEwuJxiu2AOI\n"
"nWJtC4pgnzYe7BQwHwYDVR0jBBgwFoAUsEwuJxiu2AOInWJtC4pgnzYe7BQwDwYD\n"
"VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAqkP2aFMC8v86HQygoNWn\n"
"pGOM86PkY4d8Lo2Sjfy2+L8t9V1M+1tlAH+GbPt41yxLR2BiMidugrqE3jmxPk4X\n"
"QIgrLoYSmDo1y11YzhReMVbtSyITKM+lieRWHRybkvKmW69VcY3zXSwAhbuw06LH\n"
"WggMNDIfkRWDpesjOhmv2Zg2Y/IPsVH1BzESoggpRwClglzi1SNz/uaZm29+XOld\n"
"5yoYlUxzW47P8mOZNY3UQ15N6rA5YhGfKycKP2aR9x9x8qa0hWyV1HXZ3wJmsvTk\n"
"Z+iMNJSHatq0C6HTVwwmN1JlDvdVEc1GSI9F8rjKDagB9QDHyHyqhsoMEbbRUlug\n"
"Kw==\n"
"-----END CERTIFICATE-----\n";	

    std::string const key =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2cwPDlkQYuQKI\n"
"U+v787T/G62zhrr2mdxPS6AOS8Op2IndakS1NTQOErjpVvwXkidmN7jrI8H/pyTE\n"
"+qMu+X5zBeHdPBJFv141yp/lwEsYQv1Ydo+BL1vE3OhgFhyRYf14YB0vsuOg+lB7\n"
"eyfk2nGEayQaK07GNO1Wc4hr0hKUCAH+a0mmCqKEic42DmRBxdB1tHa2/BYcrtxF\n"
"AZd/FoxcEV2rWh7eGda1njdkIYtn+ndtuDMFYhESzipfPJQbjrBFNFdEiKnYst1H\n"
"qyIeoa3sRLbsk4VXxZR+fNFXQAxfS0zx2Z+CLJRA1kfCWevD2U8Y7P3CglOpmHz5\n"
"5UA0qlqTAgMBAAECggEATLncjN1+AKmZK4yjUn7gEGJq73MK4Ba/Q+eJRUnOXHhw\n"
"Ldl5UH0xyXNNKO/ILv9rKzzmupf8hw8a0u2WP3RznVqNbBTNmGBMdbGjAaMW0Xqm\n"
"gRPG8KxiWs0Nug7Cb882IW/GBl+kA3gQ7YTSt5a3o1jNQ2YQCCGM58zJQ5KB9pca\n"
"gvnF/+a0RP1lUpbn/erG8gvWkh137D4v5/hDudhbhObilG8mHuTfgWHyoHWoxusP\n"
"8hFBi+2wA771Ge3mQiYXh9QVsOXgbmsdJwMhP+RD6bFnW9HcKMA9YUczcOhfpK/w\n"
"465EQ/ZKHfx/uUFwJ/bUKLMHDUbe6kTX47au8RT/2QKBgQDywu+Pie6p4hCB18sy\n"
"H9yv82gOUCAQknkjvA8YxAh04//Z2l+AxvzQIU9lj3m7slMX1XZBlr8Q7lQkOuuE\n"
"gf3+cP8CYDau/N4RiFBe1iaQFHsCOxGQAtFjx8M8O/kRpaUV7I+VzMn9Rju3Nbg4\n"
"OprjOBUamkk2bh6CHshI6b/j+QKBgQDAZhelh3c1HH4igk9EA8fIMH7LBRdilRcq\n"
"F4pbrJ10PK/aqYvn0Y9bJnEtpTAVQfcP4zl2JGK7nbUy5Bl50xFqSKeMpH4bdYtM\n"
"elBhXKauo7eoUZ5rQUR670J0Egg5igaKzs9Osqm8SMRIXpYWL+tr5YhH/e/tVYYs\n"
"qBEQ1q/96wKBgQCHIPs4aw7ugWeu3u+8dv/g8Rx62x7+GopT2dqNbpFGf6NrIKMI\n"
"i7suH1ySq8qXMCwQmEG7QK4aPo+XmzR+Dd3URBGuwN+viBIUsEwMfif5C21tUHP2\n"
"NZtYb1m9raR2rj22dnd2awgEc5PJ550jr3uH/y/AHyGhqqpQw9G4xGSMAQKBgA8Q\n"
"LyvDhl6/I1T6VNBjZ2HSAitM877BI3YlL6zrv8wY8D+zZIO60Xl2cgf71d7kMj6p\n"
"MJeCU8SSnVwlpaT3FHb4xz1op4Lo2gYb0W09/sLPiJKCCWAmVQE2+EH0I3a1yrtV\n"
"Y7+ql0VpgQyVczS7fbgN2XShegZf2shmRCfIVzEPAoGAGzLqXOzf6PYnXxtvyig8\n"
"I6429fmkIVr6eCTaD5uAS1RPd5+mCNEukXHjqjffEDZDzDLOWvWCa+8Ls9UZ5kw7\n"
"tlqQwK09Cx8zwm/5/tUEBAXbyz8n7e2AKvwf3rK1uZF+IzpG6pER8ngYRjAsBXKB\n"
"kdP2+dCHpqYSGE4iHBfCXj0=\n"
"-----END PRIVATE KEY-----\n";

	std::string const dh =
		"-----BEGIN DH PARAMETERS-----\n"
		"MIIBCAKCAQEArSHEEvjrc/dVLY0OkBAV+VngAfApxo3C7uL51iJ8iOxSdfaywXUf\n"
		"ta01jHLSzXICcPbOu7L3myIjss/3QHdgQTOLiLwHeuoRWpO3FTqwEOm0cEIhdsim\n"
		"ENRJehwAf8w2OFExfevRQx0iJqyOxksbpw4lYez317romD/ediXlgfK2bqL7v/H0\n"
		"8H62jma3HlneM2LR9uSPyLOxfr484wiwXN04HLixQYn2AocGGtmtI3fHhcgadBl3\n"
		"bWet9webMkXYbIkQI8OjHXZNs/ofLhEy22oNDnJ2BfsEgR85Dpr3590nk7rmkX5G\n"
		"JZfnnnCG4SwMCROpdfvFhkY+i2AGC714LwIBAg==\n"
		"-----END DH PARAMETERS-----\n";
	   
    ctx.set_password_callback(
        [](std::size_t,
            boost::asio::ssl::context_base::password_purpose)
        {
            return "test";
        });

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(
        boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh(
        boost::asio::buffer(dh.data(), dh.size()));
}

#endif
