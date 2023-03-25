import pytz
import json
from datetime import datetime, timedelta
import logging

from stix2 import DomainName, File, IPv4Address
from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression,
                   GreaterThanComparisonExpression, IsSubsetComparisonExpression,
                   FloatConstant, StringConstant)
from stix2 import (IntegerConstant, HashConstant, ObjectPath,
                   EqualityComparisonExpression, AndBooleanExpression,
                   OrBooleanExpression, ParentheticalExpression,
                   AndObservationExpression, OrObservationExpression,
                   FollowedByObservationExpression, ObservationExpression)
from stix2 import (TimestampConstant, HashConstant, ObjectPath, EqualityComparisonExpression,
                   AndBooleanExpression, WithinQualifier, RepeatQualifier, StartStopQualifier,
                   QualifiedObservationExpression, FollowedByObservationExpression,
                   ParentheticalExpression, ObservationExpression)
from stix2 import (ObservedData)
from stix2 import Bundle
from stix2patterns.validator import run_validator
from stix2patterns.v21.pattern import Pattern
import pathlib
from dendrol import Pattern as TreePattern


def make_patterns():
    '''
        make stix patterns from https://stix2.readthedocs.io/en/latest/guide/patterns.html

    '''
    patterns = {}
    # Equality Comparison expressions
    lhs = ObjectPath("domain-name", ["value"])
    patterns["state_1"] = ObservationExpression(EqualityComparisonExpression(lhs, "site.of.interest.zaz"))
    print("statement 1\t{}\n".format(patterns["state_1"]))

    lhs = ObjectPath("file", ["parent_directory_ref", "path"])
    patterns["state_2"] = ObservationExpression(EqualityComparisonExpression(lhs, "C:\\Windows\\System32"))
    print("statement 2\t{}\n".format(patterns["state_2"]))

    # Greater-than Comparison expressions
    lhs = ObjectPath("file", ["extensions", "windows-pebinary-ext", "sections[*]", "entropy"])
    patterns["state_3"] = ObservationExpression(GreaterThanComparisonExpression(lhs, FloatConstant("7.0")))
    print("statement 3\t{}\n".format(patterns["state_3"]))

    # IsSubset Comparison expressions
    lhs = ObjectPath("network-traffic", ["src_ref", "value"])
    patterns["state_4"] = ObservationExpression(
        IsSubsetComparisonExpression(lhs, StringConstant("2001:0db8:85a3:0000:0000:8a2e:0370:7334/64")))
    print("statement 4\t{}\n".format(patterns["state_4"]))

    # Compound Observation Expressions
    # AND boolean
    ece3 = EqualityComparisonExpression(ObjectPath("email-message", ["sender_ref", "value"]), "jdoe@example.com")
    ece4 = EqualityComparisonExpression(ObjectPath("email-message", ["subject"]), "Conference Info")
    patterns["state_5"] = ObservationExpression(AndBooleanExpression([ece3, ece4]))
    print("statement 5 (AND) \n{}\n".format(patterns["state_5"]))
    # AND boolean
    ece3B = EqualityComparisonExpression(ObjectPath("domain-name", ["resolves_to_refs", "value"]), "198.51.100.3")
    ece4B = EqualityComparisonExpression(ObjectPath("domain-name", ["value"]), "site.of.interest.zaz")
    patterns["state_6"] = ObservationExpression(AndBooleanExpression([ece4B, ece3B]))
    print("statement 6 (AND) v2 \n{}\n".format(patterns["state_6"]))
    # OR boolean
    ece5 = EqualityComparisonExpression(ObjectPath("url", ["value"]), "http://example.com/foo")
    ece6 = EqualityComparisonExpression(ObjectPath("url", ["value"]), "https://example.com/research/index.html")
    patterns["state_7"] = ObservationExpression(OrBooleanExpression([ece5, ece6]))
    print("statement 7 (OR) \n{}\n".format(patterns["state_7"]))

    # ( AND ) OR ( OR ) observation
    ece20 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["name"]), "foo.dll"))
    ece21 = ObservationExpression(
        EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\system\bar\foo"))
    ece22 = EqualityComparisonExpression(ObjectPath("process", ["name"]), "fooproc")
    ece23 = EqualityComparisonExpression(ObjectPath("process", ["name"]), "procfoo")
    # NOTE: we need to use AND/OR observation expression instead of just boolean
    # expressions as the operands are not on the same object-type
    aoe = ParentheticalExpression(AndObservationExpression([ece20, ece21]))
    obe2 = ObservationExpression(OrBooleanExpression([ece22, ece23]))
    patterns["state_8"] = OrObservationExpression([aoe, obe2])
    print("statement 8 (AND,OR,OR) \n{}\n".format(patterns["state_8"]))

    # FOLLOWED-BY
    ece10 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["hashes", "SHA-256"]), HashConstant(
        "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db", "SHA-256")))
    ece11 = ObservationExpression(
        EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\\system\\bar\\foo"))
    patterns["state_9"] = FollowedByObservationExpression([ece10, ece11])
    print("statement 9 (FollowedBy) \n{}\n".format(patterns["state_9"]))

    # Qualified Observation Expressions
    # WITHIN
    ece10 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["hashes", "SHA-256"]), HashConstant(
        "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db", "SHA-256")))
    ece11 = ObservationExpression(
        EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\\system\\bar\\foo"))
    fbe = FollowedByObservationExpression([ece10, ece11])
    par = ParentheticalExpression(fbe)
    patterns["state_10"] = QualifiedObservationExpression(par, WithinQualifier(300))
    print("statement 10 (WITHIN) \n{}\n".format(patterns["state_10"]))
    # REPEATS, WITHIN
    ece12 = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "type"]), "domain-name")
    ece13 = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "value"]), "example.com")
    abe2 = ObservationExpression(AndBooleanExpression([ece12, ece13]))
    patterns["state_11"] = QualifiedObservationExpression(QualifiedObservationExpression(abe2, RepeatQualifier(5)),
                                                          WithinQualifier(180))
    print("statement 11 (REPEAT, WITHIN) \n{}\n".format(patterns["state_11"]))
    # START, STOP
    ece14 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["name"]), "foo.dll"))
    ssq = StartStopQualifier(TimestampConstant('2016-06-01T00:00:00Z'), TimestampConstant('2016-07-01T00:00:00Z'))
    patterns["state_12"] = QualifiedObservationExpression(ece14, ssq)
    print("statement 12 (START-STOP) \n{}\n".format(patterns["state_12"]))

    return patterns


def make_observations():
    """
        make the observed data objects here, referencing the files in standard,
        and saving the results in the patterns directory
        with a single filename observed_tests.json
    """
    dom_id1 = "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"
    dom_id2 = "domain-name--3c10e93f-798e-52a6-a0c1-08156efab7f5"
    em1 = "email-addr--98f25ea8-d6ef-51e9-8fce-6a29236436ed"
    em2 = "email-addr--e4ee5301-b52d-59cd-a8fa-7630838c7194"
    em3 = "email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265"
    fba1 = "file--e277603e-1060-5ad4-9937-c26c97f1ca68"
    fbp1 = "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05"
    fbp2 = "file--5a27d487-c542-5f97-a131-a8866b477b46"
    fbin1 = "file--fb0419a8-f09c-57f8-be64-71a80417591c"
    net1 = "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1"
    net2 = "network-traffic--c95e972a-20a4-5307-b00d-b8393faf02c5"
    url1 = "url--c1477287-23ac-5971-a010-5c287877fa60"
    wrk1 = "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016"

    ts1 = datetime.now()
    ts2 = ts1 + timedelta(seconds=100)
    ts3 = ts1 + timedelta(seconds=400)

    obs_list = []

    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[dom_id1, dom_id2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[em1, em2, em3])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[dom_id1, dom_id2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[fba1, fba1])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[fbp1, fbp2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[dom_id1, dom_id2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[fbin1])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[net1, dom_id2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[dom_id1, net2])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[url1])
    )
    obs_list.append(
        ObservedData(first_observed=ts1, last_observed=ts2, number_observed=5, object_refs=[wrk1])
    )

    # create a bundle to save the observation data
    folder = pathlib.Path(__file__).resolve().parent
    folder = folder/"data"/"bundles"
    folder.mkdir(parents=True, exist_ok=True)
    obs_bundle = Bundle(obs_list, allow_custom=False)
    file_path = folder/"observations.json"
    with open(file_path, 'w') as file:
        file.write(obs_bundle.serialize())


def make_example_dicts():
    """
        process the patterns here in order to create the dicts that described them
        and thensave them in the patterns/results directory, with the filename=dict key,
        so state_1.json etc.
    """
    patterns = make_patterns()
    for id in patterns.keys():
        logging.info(f'Processing statement {id}')
        pattern = patterns[id]
        pattern_tree = TreePattern(str(pattern))
        dict_tree = pattern_tree.to_dict_tree()

        folder = pathlib.Path(__file__).resolve().parent
        folder = folder / "data" / "parsetrees"
        folder.mkdir(parents=True, exist_ok=True)
        file_path = folder / f"{id}.yml"

        logging.info('Writing parse tree as YAML')
        with open(file_path, 'w') as file:
            if id == 'state_12':
                # TODO: a bit of a hack here to avoid the dreadful YAML timezone issues
                start_stop = dict_tree['pattern']['observation']['qualifiers'][0]['start_stop']
                start_stop['start'] = start_stop['start'].replace(tzinfo=pytz.utc)
                start_stop['stop'] = start_stop['stop'].replace(tzinfo=pytz.utc)
                dict_tree['pattern']['observation']['qualifiers'][0]['start_stop'] = start_stop
                file.write(dict_tree.serialize())
            else:
                file.write(dict_tree.serialize())

        file_path = folder / f"{id}.json"

        logging.info('Writing parse tree as dicts')
        with open(file_path, 'w') as file:
            if id == 'state_12':
                # TODO: a bit of a hack here to avoid the dreadful YAML timezone issues
                start_stop = dict_tree['pattern']['observation']['qualifiers'][0]['start_stop']
                start_stop['start'] = start_stop['start'].replace(tzinfo=pytz.utc)
                start_stop['stop'] = start_stop['stop'].replace(tzinfo=pytz.utc)
                dict_tree['pattern']['observation']['qualifiers'][0]['start_stop'] = start_stop
                json.dump(dict_tree['pattern'], file)
            else:
                json.dump(dict_tree['pattern'], file)


# if this file is run directly, then start here
if __name__ == '__main__':
    make_observations()
    make_example_dicts()
