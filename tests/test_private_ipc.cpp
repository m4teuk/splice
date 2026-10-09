#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "net/private_ipc.h"

using namespace spl;

namespace {
std::string make_tmp() {
    char tmpl[] = "/tmp/splipcXXXXXX";
    EXPECT_NE(mkdtemp(tmpl), nullptr);
    return tmpl;
}
mode_t mode_of(const std::string& p) {
    struct stat st {};
    EXPECT_EQ(lstat(p.c_str(), &st), 0);
    return st.st_mode & 0777;
}
}  // namespace

TEST(PrivateDir, CreatesMissingDir0700) {
    const std::string d = make_tmp() + "/run";
    std::string err;
    ASSERT_TRUE(net::ensure_private_dir(d, &err)) << err;
    EXPECT_EQ(mode_of(d), 0700u);
}

TEST(PrivateDir, TightensOwnLooseDir) {
    const std::string d = make_tmp() + "/run";
    ASSERT_EQ(mkdir(d.c_str(), 0700), 0);
    ASSERT_EQ(chmod(d.c_str(), 0777), 0);
    std::string err;
    ASSERT_TRUE(net::ensure_private_dir(d, &err)) << err;
    EXPECT_EQ(mode_of(d), 0700u);
}

TEST(PrivateDir, RejectsSymlink) {
    const std::string base = make_tmp();
    const std::string target = base + "/target", link = base + "/run";
    ASSERT_EQ(mkdir(target.c_str(), 0700), 0);
    ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
    std::string err;
    EXPECT_FALSE(net::ensure_private_dir(link, &err));
    EXPECT_NE(err.find("symlink"), std::string::npos) << err;
}

TEST(PrivateDir, RejectsNonDirectory) {
    const std::string f = make_tmp() + "/run";
    FILE* fp = fopen(f.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    fclose(fp);
    std::string err;
    EXPECT_FALSE(net::ensure_private_dir(f, &err));
    EXPECT_NE(err.find("not a directory"), std::string::npos) << err;
}

TEST(PrivateDir, RejectsDirOwnedByAnotherUser) {
    if (getuid() == 0) GTEST_SKIP() << "root owns /";
    std::string err;
    EXPECT_FALSE(net::ensure_private_dir("/", &err));  // owned by root, not us
    EXPECT_NE(err.find("owned by another user"), std::string::npos) << err;
}

TEST(PeerUid, ReportsOwnUidOverSocketpair) {
    int sv[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    EXPECT_EQ(net::socket_peer_uid(sv[0]), getuid());
    EXPECT_EQ(net::socket_peer_uid(sv[1]), getuid());
    close(sv[0]);
    close(sv[1]);
}
