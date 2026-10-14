#include <gtest/gtest.h>

#include <string>

#include "peer/pipes.h"

using namespace spl::peer;

TEST(Kinds, EachOfferAnnouncesWhatItIs) {
    EXPECT_EQ(offer_kind("SHARE_FILE"), "file/1 send");
    EXPECT_EQ(offer_kind("GET_FILE"), "file/1 recv");
    EXPECT_EQ(offer_kind("SHELL"), "exec/1 pty");
    EXPECT_EQ(offer_kind("EXEC", {"backup", "--full"}), "exec/1");
    EXPECT_EQ(offer_kind("EXEC", {"PTY", "htop"}), "exec/1 pty");
    EXPECT_EQ(offer_kind("ECHO"), "raw");
    EXPECT_EQ(offer_kind("PIPE"), "raw");
}

TEST(Kinds, FileEndsNeedTheOppositeRole) {
    // what each local end needs, against what each offer is
    EXPECT_TRUE(kind_matches(offer_kind("SHARE_FILE"), local_expects("GET_FILE")));
    EXPECT_TRUE(kind_matches(offer_kind("GET_FILE"), local_expects("SHARE_FILE")));
    EXPECT_FALSE(kind_matches(offer_kind("GET_FILE"), local_expects("GET_FILE")));    // get from an inbox
    EXPECT_FALSE(kind_matches(offer_kind("SHARE_FILE"), local_expects("SHARE_FILE")));  // send to a share
    EXPECT_FALSE(kind_matches(offer_kind("SHELL"), local_expects("GET_FILE")));
    EXPECT_FALSE(kind_matches(offer_kind("ECHO"), local_expects("SHARE_FILE")));
}

TEST(Kinds, MatchingIsProtocolPlusEveryExpectedWord) {
    EXPECT_TRUE(kind_matches("exec/1 pty", "exec/1"));      // extra words are fine (run a pty)
    EXPECT_FALSE(kind_matches("exec/1", "exec/1 pty"));     // missing ones aren't (no shell w/o pty)
    EXPECT_FALSE(kind_matches("exec/2 pty", "exec/1"));     // another version is another protocol
    EXPECT_FALSE(kind_matches("raw", "file/1 send"));
    EXPECT_FALSE(kind_matches("file/1 recv send", "file/1 sendx"));
    EXPECT_FALSE(kind_matches("file/1recv", "file/1"));
}

TEST(Kinds, UnknownOrAnythingMatches) {
    EXPECT_TRUE(kind_matches("", "file/1 send"));  // an older peer says nothing: not a mismatch
    EXPECT_TRUE(kind_matches("raw", ""));          // PIPE/ECHO take whatever they reach
    EXPECT_EQ(local_expects("PIPE"), "");
    EXPECT_EQ(local_expects("ECHO"), "");
}

TEST(Kinds, PeopleGetTheCommandThatFits) {
    EXPECT_EQ(kind_usage("file/1 send", "desk", "report.pdf"), "spl get desk report.pdf");
    EXPECT_EQ(kind_usage("file/1 recv", "desk", "inbox"), "spl send desk <path>");
    EXPECT_EQ(kind_usage("file/1 recv", "desk", "media"), "spl send desk <path> --name media");
    EXPECT_EQ(kind_usage("exec/1 pty", "desk", "shell"), "spl shell desk");
    EXPECT_EQ(kind_usage("exec/1 pty", "desk", "top"), "spl shell desk --name top");
    EXPECT_EQ(kind_usage("exec/1", "desk", "backup"), "spl run desk backup");
    EXPECT_EQ(kind_usage("raw", "desk", "chat"), "spl chat desk");
    EXPECT_EQ(kind_usage("raw", "desk", "x"), "spl pipe open desk x");
    EXPECT_EQ(kind_usage("", "desk", "x"), "");
    EXPECT_EQ(kind_label("file/1 recv"), "receives files");
    EXPECT_EQ(kind_label(""), "unknown (an older spl)");
}

TEST(Kinds, PeerTextIsMadePrintable) {
    EXPECT_EQ(printable("file/1 send"), "file/1 send");
    EXPECT_EQ(printable("x\x1b]0;pwned\x07y"), "x?]0;pwned?y");
    EXPECT_EQ(printable("caf\xc3\xa9"), "caf??");
}
