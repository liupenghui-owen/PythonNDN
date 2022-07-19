Changelog
=========

0.3 (2021-11-21)
++++++++++++++++
* Add ``express_raw_interest`` function to ``NDNApp``.
* Add validator for known keys.
* Add CodeQL scanning.
* Add support to Windows CNG as a TPM backend.
* Add binary tools ``pyndntools``, ``pyndnsec`` and ``pynfdc``.
* Transition to Name Convention Rev03.
* Add automatic type conversion for ``Enum``, ``Flag`` and ``str``.
* Drop Python 3.7 support and add Python 3.10.

0.3a1-3 (2021-05-22)
++++++++++++++++++++
* Support Unix socket on Windows 10.
* Fix semaphore running in a different event loop bug.

0.3a1-2 (2021-04-29)
++++++++++++++++++++
* Handle ConnectionResetError.
* Drop Python 3.6 support.

0.3a1-1 (2021-01-31)
++++++++++++++++++++
* Transfer the repo to ``named-data/python-ndn``.
* Fix cocoapy to make it work on MacOS 11 Big Sur.
* Add more supports to NDNLPv2 (CongestionMark).
* Add dispatcher and set_interest_filter.

0.3a1 (2020-09-24)
++++++++++++++++++
* Fix the bug that registering multiple prefices at the same time leads to 403 error.
* Add Name Tree Schema.
* Add ``.devcontainer`` for VSCode Remote Containers and GitHub Codespaces.

0.2b2-2 (2020-05-26)
++++++++++++++++++++
* Change the default sock file path from ``/var/run/nfd.sock`` to ``/run/nfd.sock`` on Linux.
* Add FIB and CS management data structures
* Add ``make_network_nack``
* Recognize ``NDN_CLIENT_*`` environment variables

0.2b2-1 (2020-03-23)
++++++++++++++++++++
* Fix RuntimeWarning for hanging coroutine when main_loop raises an exception.
* Fix the issue when after_start throws an exception, the application gets stuck.
* Set raw_packet of express_interest and on_interest to be the whole packet with TL fields.

0.2b2 (2020-02-18)
++++++++++++++++++
* Switch to Apache License 2.0.
* Add NDNApp.get_original_packet_value.
* Improve NDNApp.route and NDNApp.express_interest to give access the
  original packet and signature pointers of packets.
* Fix typos in the documentation.
* Support more alternate URI format of Name Component (``seg``, ``off``, ``v``, ``t`` and ``seq``)
* Update Python version to 3.8 and add PyPy 7.2.0 in GitHub Action.
* Fix Name.to_str so its output for ``[b'\x08\x00']`` is correct.

0.2b1 (2019-11-20)
++++++++++++++++++
The initial release.
