#!/usr/bin/env python

import osquery

# This file is a helper function to connect to an existing osquery process and
# run a given query on it.


def run_query(client, query):
    results = client.extension_client().query(query)
    if results.status.code != 0:
        print("Error running the query: %s" % results.status.message)
        return

    for row in results.response:
        print("=" * 80)
        for key, val in row.iteritems():
            print("%s => %s" % (key, val))
    if len(results.response) > 0:
        print("=" * 80)


if __name__ == "__main__":
    cl = osquery.ExtensionClient(path='/tmp/osquery.ext.sock')
    cl.open()
    #run_query(cl, 'SELECT * FROM profiles;')
    #run_query(cl, 'SELECT * FROM profiles WHERE username = "adunham";')
    run_query(
        cl,
        'SELECT * FROM profile_items \
        WHERE profile_identifier = "29998254-A289-4F30-B59C-A8CE1A9F570C";'
    )
