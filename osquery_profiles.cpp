#include <osquery/sdk.h>
#include <osquery/system.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <dirent.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>


using namespace osquery;
namespace pt = boost::property_tree;


template<typename T>
using deleted_unique_ptr = std::unique_ptr<T,std::function<void(T*)>>;


/*
 * This is a helper function that mimics the closefrom() function in
 * FreeBSD/OpenBSD.
 */
void closeFrom(int lowfd) {
  deleted_unique_ptr<DIR> dirp(opendir("/dev/fd"), [](DIR *d) { closedir(d); });
  if (dirp == nullptr) {
    return;
  }

  struct dirent *dent;
  while ((dent = readdir(dirp.get())) != nullptr) {
    std::string dirname(dent->d_name);

    int fd;
    try {
      fd = std::stoi(dirname);
    } catch (const std::invalid_argument &) {
      continue;
    } catch (const std::out_of_range &) {
      continue;
    }

    if (fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp.get())) {
      close(fd);
    }
  }

  return;
}


/*
 * This is a helper function to run a subprocess and capture the output.
 */
Status runCommand(const std::vector<std::string>& command, std::string& output) {
  // Make char* array for arguments.  Don't forget to NULL-terminate!
  std::vector<char*> arguments;
  std::transform(command.begin(), command.end(),
                 std::back_inserter(arguments),
                [](const std::string& one) {
    return const_cast<char*>(one.c_str());
  });
  arguments.push_back(nullptr);

  int pipefd[2];
  pipe(pipefd);

  pid_t p = fork();
  if (p < 0) {
    return Status(1, "fork failed");
  }

  if (p == 0) {
    // Close reading end in the child.
    close(pipefd[0]);

    // Send stdout/stderr to the pipe.
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);

    // This descriptor is no longer needed.
    close(pipefd[1]);

    // Close all FDs after stderr.
    closeFrom(STDERR_FILENO + 1);

    // Run the subprocess (never returns)
    execv(arguments[0], &arguments[0]);
    exit(100);
  }

  // If we reach here, we're in the parent process.

  // Close the write end of the pipe.
  close(pipefd[1]);

  // Repeatedly read the child's stdout into our buffer.
  size_t num;
  char buffer[1024];
  while (true) {
    num = read(pipefd[0], buffer, sizeof(buffer));
    if (num <= 0) {
      break;
    }

    output.append(buffer, num);
  }

  // If we get here, presumably the read() from above returned either 0 or an
  // error; get the exit code.
  int status;
  if (waitpid(p, &status, 0) == -1) {
    return Status(1, "waitpid failed");
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return Status(1, "subprocess errored");
  }

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
    if (runCommand({"/usr/bin/profiles", "-C", "-o", "stdout-xml"}, commandOutput).ok()) {
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
        std::vector<std::string> command = {"/usr/bin/profiles", "-L", "-o", "stdout-xml", "-U", username};

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
      std::make_tuple("username", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("type", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("identifier", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("display_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("description", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("organization", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("verified", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("removal_allowed", INTEGER_TYPE, ColumnOptions::DEFAULT),

      // TODO: add a 'version' column with the 'ProfileVersion' key?
      //std::make_tuple("version", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    // NOTE: If there's an error, we just ignore it and return the current set
    // of results.
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
      std::make_tuple("username", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("profile_identifier", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("type", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("identifier", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("display_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("description", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("organization", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("content", TEXT_TYPE, ColumnOptions::DEFAULT),

      // TODO: add a 'version' column with the 'PayloadVersion' key?
      //std::make_tuple("version", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    // All profiles we want to read.
    auto wantedProfiles = request.constraints["profile_identifier"].getAll(EQUALS);

    // For all profiles that match our constraints...
    // NOTE: If there's an error, we just ignore it and return the current set
    // of results.
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
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

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
