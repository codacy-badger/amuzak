 ![Logo](https://github.com/ampcore/amuzak/raw/master/themes/rezak/images/amuzak-light.png)

aMuzak
=======

[amuzak@github.com](https://github.com/ampcore/amuzak/)

**Notice:**  THIS IS A FORK OF AMPACHE THAT WILL FOCUS ON THE MUSIC

- Video features will not be used in aMuzak.
- You can upgrade from Ampache to aMuzak but will not be able to go
back. I recommend copying your database to allow you to keep your
Ampache server running.
- Things are really stable now. Really happy with the progress made so far.

Basics
------

aMuzak is a web based audio streaming application and file
manager allowing you to access your music from anywhere,
using almost any internet enabled device.

aMuzak's usefulness is heavily dependent on being able to extract
correct metadata from embedded tags in your files and/or the file name.
aMuzak is not a media organiser; it is meant to be a tool which
presents an already organised collection in a useful way. It assumes
that you know best how to manage your files and are capable of
choosing a suitable method for doing so.

Recommended Version
-------------------

The recommended and most stable version is [git HEAD](https://github.com/ampcore/amuzak/archive/master.tar.gz).
[![Build Status](https://api.travis-ci.org/ampcore/amuzak.svg?branch=master)](https://travis-ci.org/ampcore/amuzak)

You get the latest version with recent changes and fixes but maybe in an unstable state from our [develop branch](https://github.com/ampcore/amuzak/archive/develop.tar.gz).
[![Build Status](https://api.travis-ci.org/ampcore/amuzak.svg?branch=develop)](https://travis-ci.org/ampcore/amuzak)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/ampcore/amuzak/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/ampcore/amuzak/?branch=develop)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2a10f9b966a5457da6c44853be600c52)](https://app.codacy.com/app/lachlan-00/amuzak)
[![Code Climate](https://api.codeclimate.com/v1/badges/7f56af9bd0c8302348c7/maintainability.svg)](https://codeclimate.com/github/ampcore/amuzak)

Installation
------------

Please see [the wiki](https://github.com/ampcore/amuzak/wiki/Installation)

Requirements
------------

- A web server. All of the following have been used, though Apache
receives the most testing:
  - Apache
  - lighttpd
  - nginx
  - IIS

- PHP 5.6 or greater.

- PHP modules:
  - PDO
  - PDO_MYSQL
  - hash
  - session
  - json
  - simplexml (optional)
  - curl (optional)

  - For FreeBSD The following modules must be loaded:
    - php-xml
    - php-dom

- MySQL 5.x

Upgrading
---------

If you are upgrading from an older version of aMuzak we recommend
moving the old directory out of the way, extracting the new copy in
its place and then copying the old /config/amuzak.cfg.php, /rest/.htaccess,
and /play/.htaccess files if any. All database updates will be handled by aMuzak.

License
-------

aMuzak is free software; you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License v3 (AGPLv3)
as published by the Free Software Foundation.

aMuzak includes some [external modules](https://github.com/ampache/ampache/blob/develop/composer.lock) that carry their own licensing.

Translations
------------

aMuzak is currently translated (at least partially) into the
following languages. If you are interested in updating an existing
translation, simply visit us on [Transifex](https://www.transifex.com/ampachecore/amuzak).
If you prefer it old school or want to work offline, take a look at [/locale/base/TRANSLATIONS](https://github.com/ampcore/amuzak/blob/develop/locale/base/TRANSLATIONS.md)
for more instructions.

Translation progress so far:
**Please Help Review Google Machine Learing Translations!**

[![](https://www.transifex.com/_/charts/redirects/ampachecore/amuzak/image_png/config/)](https://www.transifex.com/projects/p/amuzak/)

Credits
-------

Thanks to all those who have helped make aMuzak awesome: [Credits](docs/ACKNOWLEDGEMENTS)


Contact Us
----------

Hate it? Love it? Let us know! Dozens of people send ideas for amazing new features, report bugs and further develop aMuzak actively. Be a part of aMuzak with it's more than 10 years long history and get in touch with an awesome and friendly community!

- For Live discussions, visit us on our IRC Channel at chat.freenode.net #ampache or alternative via a [web based chat client](https://webchat.freenode.net)

- For harder cases or general discussion about aMuzak take a look at our [Google Groups Forum](https://groups.google.com/forum/#!forum/ampache)
- Found a bug or aMuzak isn't working as expected? Please refer to the [Issues Template](https://github.com/ampcore/amuzak/wiki/Issues) and head over to our [Issue Tracker](https://github.com/ampcore/amuzak/issues)

Further Information and basic Help
----------------------------------

- Everything related to the aMuzak Project can be found on our [Public Repository](https://github.com/ampcore)
- Want to know, how to get Apache to work or learn more about the functions? See our [Documentation](https://github.com/ampcore/amuzak/wiki)

We hope to see you soon and that you have fun with this Project!

[Team aMuzak](docs/ACKNOWLEDGEMENTS)
