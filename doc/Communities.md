# Communities


## Names

As communities designate virtual networks, they must be distinguishable from each other. Its their name that makes them distinguishable and which therefore should be unique per network. The community name is composed of 19 byte-sized characters and it internally always is terminated by an additional zero character totalling up to 20 characters. Hence, the zero character cannot be part of the regular community name. There are some other characters that cannot be used, namely `. * + ? [ ] \`.

To make full use of character space, hex values could be used, e.g. from Linux bash applying the `edge … -c $(echo -en '\x3a\x3b\x4a\x6a\xfa') …` command line syntax. If used with a configuration file, the bytes must be directly filled as characters into a corresponding `-c :;Jjþ` line.

Apart from command line `-c` and configuration file, the community name can be supplied through the `N2N_COMMUNITY` environment variable. This might prove useful to hide the community name from command line if used with header encryption enabled, see below.


## Restrict Supernode Access

By default, a supernode offers its service to all communities and allows them to connect. If a self-setup supernode shall handle certain communities only, the supernode can be given a list of allowed communities. This list is a simple text file containg the allowed community names, one per line:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity
 yourCommunity
```

This file is provided to the supernode through the `-c community.list` command line parameter. This example would allow the supernode to only accept connections from communities called "myCommunity" and "yourCommunity", these are fixed-name communities.


## Somewhat Flexible Community Names

If you want to allow all community names from a certain name range, e.g. from "myCommunity00" to "myCommunity99", the `community.list` file (or whatever you name it) could look as follows:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity[0-9][0-9]
```

Advanced users recognize the so called regular expression. To prevent users from stop reading, the author did not dare to name this section "Regular Expressions". Anyway, community names can be provided as regular expressions using the following placeholders:

```
 '.'        Dot, matches any character
 '*'        Asterisk, match zero or more of previous element (greedy)
 '+'        Plus, match one or more of previous element (greedy)
 '?'        Question, match zero or one (non-greedy)
 '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'}  (feature is currently broken)
 '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 '\s'       Whitespace, \t \f \r \n \v and spaces
 '\S'       Non-whitespace
 '\w'       Alphanumeric, [a-zA-Z0-9_]
 '\W'       Non-alphanumeric
 '\d'       Digits, [0-9]
 '\D'       Non-digits
```

Knowing this, we can as well express the exemplary `community.list` above the following way:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity\d\d
```

Also, as the `. * + ? [ ] \` characters indicate parts of regular expressions, we now understand why those are not allowed in fixed-name community names.


## Header Encryption

By default, the community name is transmitted in plain witch each packet. So, a fixed-name community might keep your younger siblings out of your community (as long as they do not know the community name) but sniffing attackers will find out the community name. Using this name, they will be able to access it by just connecting to the supernode then.

[Header encryption](Crypto.md#header) can be enabled to prevent plain transmission. It is important to understand that header encryption, if enabled, only works on fixed-name communities. It will not work on community names described by regular expressions.

On the other hand, the provision of fixed-name communities blocks all other, non-listed communities. To allow a mixed operation of certain encrypted and hence fixed-name communities along with all other open communities, the following "trick" can be applied:

```
 # community.list (a text file)
 -----------------------------------------------------
 mySecretCom
 .*
```

This is not really a trick but just making use of a very permissive regular expression at the second line.
