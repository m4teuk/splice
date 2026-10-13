#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

#include "peer/store.h"

using namespace spl::peer;

namespace {
Store temp_store() {
    char tmpl[] = "/tmp/splsetXXXXXX";
    EXPECT_NE(mkdtemp(tmpl), nullptr);
    setenv("SPL_CONFIG_DIR", tmpl, 1);
    return *Store::open(nullptr);
}
ConnRecord rec(const std::string& name) {
    ConnRecord r;
    r.name = name;
    r.uid[0] = 7;
    return r;
}
}  // namespace

TEST(PeerSettings, DefaultOnAndRoundTrip) {
    Store st = temp_store();
    ConnRecord r = rec("laptop");
    EXPECT_TRUE(r.use_relay && r.lan_discovery && r.remember_address);
    r.use_relay = false;
    r.addresses = {"10.0.0.5", "laptop.example.net:7701"};
    ASSERT_TRUE(st.save(r, nullptr));
    const auto got = st.load("laptop");
    ASSERT_TRUE(got.has_value());
    EXPECT_FALSE(got->use_relay);
    EXPECT_TRUE(got->lan_discovery);
    EXPECT_TRUE(got->remember_address);
    EXPECT_EQ(got->addresses, r.addresses);
    EXPECT_EQ(settings_summary(*got), "relay off \u00b7 lan-discovery on \u00b7 remember-address on");
}

TEST(PeerSettings, LanPortIsStoredOnlyWhenNotDefault) {
    Store st = temp_store();
    ConnRecord r = rec("laptop");
    ASSERT_TRUE(st.save(r, nullptr));
    EXPECT_EQ(st.load("laptop")->lan_port, 0);
    EXPECT_EQ(settings_summary(*st.load("laptop")).find("lan-port"), std::string::npos);
    r.lan_port = 9000;
    ASSERT_TRUE(st.save(r, nullptr));
    EXPECT_EQ(st.load("laptop")->lan_port, 9000);
    EXPECT_NE(settings_summary(*st.load("laptop")).find("lan-port 9000"), std::string::npos);
}

TEST(PeerSettings, LearnedPortFollowsRenameAndRemove) {
    Store st = temp_store();
    ASSERT_TRUE(st.save(rec("a"), nullptr));
    EXPECT_EQ(st.load_learned_port("a"), 0);
    ASSERT_TRUE(st.save_learned_port("a", 9100));
    EXPECT_EQ(st.load_learned_port("a"), 9100);
    ASSERT_TRUE(st.rename("a", "b", nullptr));
    EXPECT_EQ(st.load_learned_port("a"), 0);
    EXPECT_EQ(st.load_learned_port("b"), 9100);
    ASSERT_TRUE(st.save_learned_port("b", 0));  // 0 = forget
    EXPECT_EQ(st.load_learned_port("b"), 0);
    ASSERT_TRUE(st.save_learned_port("b", 9200));
    ASSERT_TRUE(st.remove("b"));
    EXPECT_EQ(st.load_learned_port("b"), 0) << "a later peer reusing the name must start clean";
}

TEST(PeerSettings, RememberedAddressesFollowRenameAndRemove) {
    Store st = temp_store();
    ASSERT_TRUE(st.save(rec("a"), nullptr));
    ASSERT_TRUE(st.save_seen("a", {{"192.168.1.20:41641", 100}, {"[fd00::5]:7", 50}}));
    auto seen = st.load_seen("a");
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen[0].addr, "192.168.1.20:41641");
    EXPECT_EQ(seen[0].when_unix, 100);
    EXPECT_EQ(seen[1].addr, "[fd00::5]:7");

    ASSERT_TRUE(st.rename("a", "b", nullptr));
    EXPECT_TRUE(st.load_seen("a").empty());
    EXPECT_EQ(st.load_seen("b").size(), 2u);

    ASSERT_TRUE(st.save_seen("b", {}));  // empty = forget
    EXPECT_TRUE(st.load_seen("b").empty());
    ASSERT_TRUE(st.save_seen("b", {{"10.0.0.1:1", 1}}));
    ASSERT_TRUE(st.remove("b"));
    EXPECT_TRUE(st.load_seen("b").empty()) << "a later peer reusing the name must start clean";
}
