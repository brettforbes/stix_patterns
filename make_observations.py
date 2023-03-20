import json
from loguru import logger
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
from stix2patterns.validator import run_validator
from stix2patterns.v21.pattern import Pattern


def make_patterns():
    '''
        make stix patterns from https://stix2.readthedocs.io/en/latest/guide/patterns.html

    '''
    patterns = {}
    # Equality Comparison expressions
    lhs = ObjectPath("domain-name", ["value"])
    patterns["state_1"] = ObservationExpression(EqualityComparisonExpression(lhs, "site.of.interest.zaz"))
    print("statement 1\t{}\n".format(patterns["state_1"]))

    lhs = ObjectPath("file", ["parent_directory_ref","path"])
    patterns["state_2"] = ObservationExpression(EqualityComparisonExpression(lhs, "C:\\Windows\\System32"))
    print("statement 2\t{}\n".format(patterns["state_2"]))

    # Greater-than Comparison expressions
    lhs = ObjectPath("file", ["extensions", "windows-pebinary-ext", "sections[*]", "entropy"])
    patterns["state_3"] = ObservationExpression(GreaterThanComparisonExpression(lhs, FloatConstant("7.0")))
    print("statement 3\t{}\n".format(patterns["state_3"]))

    # IsSubset Comparison expressions
    lhs = ObjectPath("network-traffic", ["src_ref", "value"])
    patterns["state_4"] = ObservationExpression(IsSubsetComparisonExpression(lhs, StringConstant("2001:0db8:85a3:0000:0000:8a2e:0370:7334/64")))
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
    ece21 = ObservationExpression(EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\system\bar\foo"))
    ece22 = EqualityComparisonExpression(ObjectPath("process", ["name"]), "fooproc")
    ece23 = EqualityComparisonExpression(ObjectPath("process", ["name"]), "procfoo")
    # NOTE: we need to use AND/OR observation expression instead of just boolean
    # expressions as the operands are not on the same object-type
    aoe = ParentheticalExpression(AndObservationExpression([ece20, ece21]))
    obe2 = ObservationExpression(OrBooleanExpression([ece22, ece23]))
    patterns["state_8"] = OrObservationExpression([aoe, obe2])
    print("statement 8 (AND,OR,OR) \n{}\n".format(patterns["state_8"]))

    # FOLLOWED-BY
    ece10 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["hashes", "SHA-256"]), HashConstant("fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db", "SHA-256")))
    ece11 = ObservationExpression(EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\\system\\bar\\foo"))
    patterns["state_9"] = FollowedByObservationExpression([ece10, ece11])
    print("statement 9 (FollowedBy) \n{}\n".format(patterns["state_9"]))

    # Qualified Observation Expressions
    # WITHIN
    ece10 = ObservationExpression(EqualityComparisonExpression(ObjectPath("file", ["hashes", "SHA-256"]), HashConstant("fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db", "SHA-256")))
    ece11 = ObservationExpression(EqualityComparisonExpression(ObjectPath("win-registry-key", ["key"]), "hkey_local_machine\\system\\bar\\foo"))
    fbe = FollowedByObservationExpression([ece10, ece11])
    par = ParentheticalExpression(fbe)
    patterns["state_10"] = QualifiedObservationExpression(par, WithinQualifier(300))
    print("statement 10 (WITHIN) \n{}\n".format(patterns["state_10"]))
    # REPEATS, WITHIN
    ece12 = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "type"]), "domain-name")
    ece13 = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "value"]), "example.com")
    abe2 = ObservationExpression(AndBooleanExpression([ece12, ece13]))
    patterns["state_11"] = QualifiedObservationExpression(QualifiedObservationExpression(abe2, RepeatQualifier(5)), WithinQualifier(180))
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
        and saving the results in the patterns/results directory
    """


def make_example_dicts():
    """
        process the patterns here in order to create the dicts that described them
    """
    patterns = make_patterns()


# if this file is run directly, then start here
if __name__ == '__main__':
    make_observations()
