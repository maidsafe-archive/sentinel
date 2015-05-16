# Sentinel

**Primary Maintainer:**     Peter Jankuliak (peter.jankuliak@maidsafe.net)

**Secondary Maintainer:**   Benjamin Bollen (benjamin.bollen@maidsafe.net)

Confirm group based consensus on messages in a p2p network

|Crate|Travis|Windows|OSX|Coverage|
|:------:|:-------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/sentinel)](https://crates.io/crates/sentinel)|[![Build Status](https://travis-ci.org/maidsafe/sentinel.svg?branch=master)](https://travis-ci.org/maidsafe/sentinel)| [![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=self_encryption_win64_status_badge)](http://ci.maidsafe.net:8080/job/self_encryption_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=self_encryption_osx_status_badge)](http://ci.maidsafe.net:8080/job/self_encryption_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/dirvine/sentinel/badge.svg)](https://coveralls.io/r/dirvine/sentinel)|

| [API Documentation](http://maidsafe.github.io/sentinel/sentinel/)| [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview

###Pre-requisite:
None

##Todo Items

- [x] Restructure generic types
- [ ] Move Frequency to separate Statistics crate as it is used by Sentinel, but equally by routing for merging messages
- [ ] Replace return type Option<(Request, MergedMessageFromClaims)> to rx-channel

##External Todo Items

- [ ] On Accumulator crate:
    - [ ] Only store one value on identical values received
