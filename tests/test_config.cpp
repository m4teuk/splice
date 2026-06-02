#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <string>

#include "common/config.h"

using namespace spl;

TEST(Config, ParsesSections) {
    char tmpl[] = "/tmp/splcfgXXXXXX";
    ASSERT_NE(mkdtemp(tmpl), nullptr);
    setenv("SPL_CONFIG_DIR", tmpl, 1);
    {
        std::ofstream f(std::string(tmpl) + "/config");
        f << "# a comment\n"
             "[server]\n"
             "addr = ::\n"
             "port = 9000\n"
             "\n"
             "[peer]\n"
             "addr = relay.example\n"
             "port = 7000\n";
    }
    Config c = load_config();
    EXPECT_EQ(c.server.addr, "::");
    EXPECT_EQ(c.server.port, 9000);
    EXPECT_EQ(c.peer.addr, "relay.example");
    EXPECT_EQ(c.peer.port, 7000);
    unsetenv("SPL_CONFIG_DIR");
}

TEST(Config, MissingFileIsEmpty) {
    char tmpl[] = "/tmp/splcfg2XXXXXX";
    ASSERT_NE(mkdtemp(tmpl), nullptr);
    setenv("SPL_CONFIG_DIR", tmpl, 1);
    Config c = load_config();
    EXPECT_TRUE(c.server.addr.empty());
    EXPECT_EQ(c.server.port, 0);
    EXPECT_TRUE(c.peer.addr.empty());
    unsetenv("SPL_CONFIG_DIR");
}
