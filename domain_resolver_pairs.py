#! /usr/bin/env python3

"""
This will take in two files and write to a third, all provided on the command
line

One is a file where each line is a JSON object. Each JSON object has a "domain"
field.

The second file is a list of paired resolvers. Each line has the format:
<v6 address> <v4 address> <country code>

This program will form the cross product of the domains and each IP address as
long as the country code is for a single country (some lines have multiple
country codes, if the v4 and v6 address have different countries.)
"""

import argparse
import json

def setup_args() -> argparse.Namespace:
    """
    Grabs command lines arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "domain_json_file", help="Path to the file containing JSON object on each domain"
    )
    parser.add_argument("resolver_file", help="Path to the file containing resolvers")
    parser.add_argument(
        "v4_cartesian_file",
        help="Path to the file to write the cartesian product, with v4 resolvers"
    )
    parser.add_argument(
        "v6_cartesian_file",
        help="Path to the file to write the cartesian product, with v6 resolvers"
    )
    return parser.parse_args()

def cartesian_product(
    domain_file: str,
    resolver_file: str,
    v4_output_file: str,
    v6_output_file: str
) -> None:
    """
    This will open the output file and write to it, one line at a time a domain
    and a resolver, as long as both the v4 and v6 resolvers share the same country.
    """
    print("Writing cartesian product to {} and {}".format(v4_output_file, v6_output_file))

    with open(v4_output_file, 'w+') as v4_write_file, open(v6_output_file, 'w+') as v6_write_file:
        with open(domain_file, 'r') as domain_json_file:
            for json_string in domain_json_file.readlines():
                json_dict = json.loads(json_string)
                domain = json_dict["domain"]
                with open(resolver_file, 'r') as resolver_pairs_file:
                    for resolvers_string in resolver_pairs_file.readlines():
                        if "!!" in resolvers_string:
                            continue
                        try:
                            split_resolvers = resolvers_string.split(" ")
                            v6_address = split_resolvers[0].strip()
                            if split_resolvers[1] == " ":
                                # there are double spaces between items
                                v4_address = split_resolvers[2].strip()
                            else:
                                v4_address = split_resolvers[1].strip()
                        except ValueError:
                            print("Couldn't split line: {}".format(resolvers_string))
                        v6_write_file.write("{},[{}]\n".format(domain, v6_address))
                        v4_write_file.write("{},{}\n".format(domain, v4_address))

if __name__ == "__main__":
    args = setup_args()
    cartesian_product(
        args.domain_json_file,
        args.resolver_file,
        args.v4_cartesian_file,
        args.v6_cartesian_file,
    )
