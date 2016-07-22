#include <osquery/sdk.h>

#include <iomanip>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>


using namespace osquery;
namespace pt = boost::property_tree;


/*
 * This is a helper function to run a subprocess and capture the output.
 */
Status runCommand(const std::string& command, std::string& output) {
  char buffer[1024] = {0};

  FILE* stream = popen(command.c_str(), "r");
  if (stream == nullptr) {
    return Status(1);
  }

  output.clear();
  while (fgets(buffer, sizeof(buffer), stream) != nullptr) {
    output.append(buffer);
  }

  pclose(stream);
  return Status(0, "OK");
}


/*
 * Helper function, mostly copied from osquery's source code.
 *
 * This function extracts a list of usernames given in the input query.
 */
QueryData usersFromContext(const QueryContext& context, bool all = false) {
  QueryData users;

  // If the user gave a 'username' constraint, get the user with that username
  // (this will helpfully also not do anything if the user does not exist).
  if (context.hasConstraint("username", EQUALS)) {
    context.forEachConstraint(
        "username",
        EQUALS,
        ([&users](const std::string& expr) {
          auto user = SQL::selectAllFrom("users", "username", EQUALS, expr);
          users.insert(users.end(), user.begin(), user.end());
        }));
  } else if (!all) {
    // The user did not give a username, and did not want everything - return
    // ourselves.
    users =
        SQL::selectAllFrom("users", "uid", EQUALS, std::to_string(getuid()));
  } else {
    // Return all users.
    users = SQL::selectAllFrom("users");
  }
  return users;
}


/*
 * This helper function will parse the output of the `profiles` command and
 * call the given callback with each parsed result.
 */
template<typename Fn>
Status parseProfile(const std::string& commandOutput, const std::string& username, Fn callback) {
  // Handle the case where the user does not exist.
  if (boost::starts_with(commandOutput, "profiles: the user could not be found")) {
    return Status(1, "User not found");
  }

  // The root key of the plist is either the username, or the literal string
  // "_computerlevel" for system-wide profiles.
  std::string rootKey;
  if (username.length() > 0) {
    rootKey = username;
  } else {
    rootKey = "_computerlevel";
  }

  pt::ptree tree;
  if (parsePlistContent(commandOutput, tree).ok()) {
    pt::ptree root;

    try {
      root = tree.get_child(rootKey);
    } catch (const pt::ptree_bad_path&) {
      return Status(1, "No profiles");
    }

    for (const auto& it : root) {
      auto profile = it.second;
      callback(username, profile);
    }
  }

  return Status(0, "OK");
}


/*
 * This helper function will extract all usernames from the given context (if
 * any), run the `profiles` tool to retrieve all profiles for those users, and
 * then call the given callback with the resulting parsed profile data.
 */
template<typename Fn>
Status iterateProfiles(QueryContext& request, Fn callback) {
  std::string commandOutput;

  // If the caller is requesting a join against the user, then we generate
  // information from that user - otherwise, we grab the system-wide
  // profiles.
  if (request.constraints["username"].notExistsOrMatches("")) {
    // Get system profiles
    if (runCommand("/usr/bin/profiles -C -o stdout-xml", commandOutput).ok()) {
      // TODO: error handling
      auto result = parseProfile(commandOutput, "", callback);
      if (!result.ok()) {
        return result;
      }
    }
  } else {
    auto users = usersFromContext(request);
    for (const auto& row : users) {
      if (row.count("username") > 0) {
        auto username = row.at("username");

        // NOTE: This is somewhat vulnerable to shell injection.  Currently,
        // we're "safe" because the `usersFromContext` function only returns
        // rows where the user actually exists - take care.
        auto command = "/usr/bin/profiles -L -o stdout-xml -U " + username;

        if (runCommand(command, commandOutput).ok()) {
          auto result = parseProfile(commandOutput, username, callback);
          if (!result.ok()) {
            return result;
          }
        }
      }
    }
  }

  return Status(0, "OK");
}


/*
 * This table plugin creates the `profiles` table, which returns all
 * configuration profiles that are currently installed on the system.
 */
class ProfilesTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
      std::make_tuple("username", TEXT_TYPE, DEFAULT),
      std::make_tuple("type", TEXT_TYPE, DEFAULT),
      std::make_tuple("identifier", TEXT_TYPE, DEFAULT),
      std::make_tuple("display_name", TEXT_TYPE, DEFAULT),
      std::make_tuple("description", TEXT_TYPE, DEFAULT),
      std::make_tuple("organization", TEXT_TYPE, DEFAULT),
      std::make_tuple("verified", INTEGER_TYPE, DEFAULT),
      std::make_tuple("removal_allowed", INTEGER_TYPE, DEFAULT),

      // TODO: add a 'version' column with the 'ProfileVersion' key?
      //std::make_tuple("version", INTEGER_TYPE, DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    // TODO: do we want to handle error returns here?
    iterateProfiles(request, [&](const std::string& username, pt::ptree& profile) {
      Row r;
      r["username"] = username;
      r["identifier"] = profile.get<std::string>("ProfileIdentifier", "");
      r["display_name"] = profile.get<std::string>("ProfileDisplayName", "");
      r["description"] = profile.get<std::string>("ProfileDescription", "");
      r["organization"] = profile.get<std::string>("ProfileOrganization", "");
      r["type"] = profile.get<std::string>("ProfileType", "");

      if (profile.get<std::string>("ProfileVerificationState", "") == "verified") {
        r["verified"] = INTEGER(1);
      } else {
        r["verified"] = INTEGER(0);
      }

      // The flag is actually 'ProfileRemovalDisallowed', which is set to 'true' when the
      // profile cannot be removed.
      if (profile.get<std::string>("ProfileRemovalDisallowed", "") == "true") {
        r["removal_allowed"] = INTEGER(0);
      } else {
        r["removal_allowed"] = INTEGER(1);
      }

      results.push_back(r);
    });

    return results;
  }
};


/*
 * This table plugin creates the `profile_items` table, which returns all
 * items in the given configuration profile.
 */
class ProfileItemsTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
      std::make_tuple("username", TEXT_TYPE, DEFAULT),
      std::make_tuple("profile_identifier", TEXT_TYPE, DEFAULT),
      std::make_tuple("type", TEXT_TYPE, DEFAULT),
      std::make_tuple("identifier", TEXT_TYPE, DEFAULT),
      std::make_tuple("display_name", TEXT_TYPE, DEFAULT),
      std::make_tuple("description", TEXT_TYPE, DEFAULT),
      std::make_tuple("organization", TEXT_TYPE, DEFAULT),
      std::make_tuple("content", TEXT_TYPE, DEFAULT),

      // TODO: add a 'version' column with the 'PayloadVersion' key?
      //std::make_tuple("version", INTEGER_TYPE, DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    // All profiles we want to read.
    auto wantedProfiles = request.constraints["profile_identifier"].getAll(EQUALS);

    // For all profiles that match our constraints...
    // TODO: do we want to handle error returns here?
    iterateProfiles(request, [&](const std::string& username, pt::ptree& profile) {
      // Get this profile's identifier.
      auto identifier = profile.get<std::string>("ProfileIdentifier", "");

      // If we don't care about this profile, we just continue.
      if (wantedProfiles.find(identifier) == wantedProfiles.end()) {
        return;
      }

      // Find all payloads in this profile, continuing if there are none.
      pt::ptree payloads;
      try {
        payloads = profile.get_child("ProfileItems");
      } catch (const pt::ptree_bad_path&) {
        return;
      }

      for (const auto& it : payloads) {
        auto payload = it.second;

        Row r;
        r["profile_identifier"] = identifier;
        r["type"] = payload.get<std::string>("PayloadType", "");
        r["identifier"] = payload.get<std::string>("PayloadIdentifier", "");
        r["display_name"] = payload.get<std::string>("PayloadDisplayName", "");
        r["description"] = payload.get<std::string>("PayloadDescription", "");
        r["organization"] = payload.get<std::string>("PayloadOrganization", "");

        std::string content;
        try {
          std::ostringstream buf;
          pt::write_json(buf, payload.get_child("PayloadContent"), false);
          buf.flush();

          content = buf.str();
        } catch (const pt::ptree_bad_path&) {
          // Do nothing.
        }

        boost::algorithm::trim_right(content);
        r["content"] = content;
        results.push_back(r);
      }
    });

    return results;
  }
};

REGISTER_EXTERNAL(ProfilesTablePlugin, "table", "profiles");
REGISTER_EXTERNAL(ProfileItemsTablePlugin, "table", "profile_items");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);

  // Connect to osqueryi or osqueryd.
  auto status = startExtension("profiles", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
