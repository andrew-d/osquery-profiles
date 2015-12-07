#include <osquery/sdk.h>

#include <iomanip>
#include <sstream>

#include <boost/algorithm/string.hpp>
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
 * This table plugin creates the `profiles` table, which returns all
 * configuration profiles that are currently installed on the system.
 */
class ProfilesTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
      {"type", TEXT_TYPE},
      {"identifier", TEXT_TYPE},
      {"display_name", TEXT_TYPE},
      {"description", TEXT_TYPE},
      {"organization", TEXT_TYPE},
      {"verified", INTEGER_TYPE},
      {"removal_allowed", INTEGER_TYPE},

      // TODO: add a 'version' column with the 'ProfileVersion' key?
      //{"version", INTEGER_TYPE},
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;
    std::string commandOutput;

    // Get system profiles
    if (runCommand("/usr/bin/profiles -C -o stdout-xml", commandOutput).ok()) {
      genProfilesFromOutput(commandOutput, results);
    }

    // Get user profiles
    if (runCommand("/usr/bin/profiles -L -o stdout-xml", commandOutput).ok()) {
      genProfilesFromOutput(commandOutput, results);
    }

    return results;
  }

  void genProfilesFromOutput(const std::string& output, QueryData& results) {
    pt::ptree tree;
    if (parsePlistContent(output, tree).ok()) {
      pt::ptree root;

      try {
        // TODO: this might be the current username for per-user profiles?
        root = tree.get_child("_computerlevel");
      } catch (const pt::ptree_bad_path&) {
        return;
      }

      for (const auto& it : root) {
        auto profile = it.second;

        Row r;
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
      }
    }
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
      {"profile_identifier", TEXT_TYPE},
      {"type", TEXT_TYPE},
      {"identifier", TEXT_TYPE},
      {"display_name", TEXT_TYPE},
      {"description", TEXT_TYPE},
      {"organization", TEXT_TYPE},
      {"content", TEXT_TYPE},

      // TODO: add a 'version' column with the 'PayloadVersion' key?
      //{"version", INTEGER_TYPE},
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;
    std::string commandOutput;
    std::map<std::string, pt::ptree> profileMap;

    // Get system profiles
    if (runCommand("/usr/bin/profiles -C -o stdout-xml", commandOutput).ok()) {
      loadProfilesFromOutput(commandOutput, profileMap);
    }

    // Get user profiles
    if (runCommand("/usr/bin/profiles -L -o stdout-xml", commandOutput).ok()) {
      loadProfilesFromOutput(commandOutput, profileMap);
    }

    // For each profile identifier given...
    auto identifiers = request.constraints["profile_identifier"].getAll(EQUALS);
    for (const auto& identifier : identifiers) {
      // If we have this profile, we dump information about it.
      auto search = profileMap.find(identifier);
      if (search != profileMap.end()) {
        auto identifier = search->first;

        pt::ptree payloads;

        try {
          payloads = search->second.get_child("ProfileItems");
        } catch (const pt::ptree_bad_path&) {
          continue;
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
      }
    }

    return results;
  }

  void loadProfilesFromOutput(const std::string& output, std::map<std::string, pt::ptree>& profiles) {
    pt::ptree tree;
    if (parsePlistContent(output, tree).ok()) {
      pt::ptree root;

      try {
        // TODO: this might be the current username for per-user profiles?
        root = tree.get_child("_computerlevel");
      } catch (const pt::ptree_bad_path&) {
        return;
      }

      for (const auto& it : root) {
        auto profileTree = it.second;
        auto identifier = profileTree.get<std::string>("ProfileIdentifier", "");
        profiles[identifier] = profileTree;
      }
    }
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
  }

  // Finally shutdown.
  runner.shutdown();
  return 0;
}
