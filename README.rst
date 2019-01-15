REMME Core
==========

|Jenkins| |Docker Stars| |Gitter|

REMME is a blockchain-based protocol used for issuing and management of X.509
client certificates to resolve issues related to cybersecurity, IoT
connectivity, data integrity, digital copyright protection, transparency etc. 

REMME Core is built on Hyperledger Sawtooth platform, allowing to be flexible in
language choice during the development process. REMME Core supports JS, .NET,
that’s why you to easily embed REMME Core in your project. 

🔖 Documentation
----------------

🔖 `Architecture overview <https://youtu.be/fw3591g0hiQ>`_

🔖 `Docs & tutorials <https://docs.remme.io/>`_

🔖 `REMME use case for IoT
<https://blog.aira.life/blockchain-as-refinery-for-industrial-iot-data-873b320a6ff0>`_

🔖 `Blog <https://medium.com/remme>`_ & `talks <https://gitter.im/REMME-Tech>`_

How to build on REMME Core
--------------------------

1. REMChain is one of the components of our solution and a basic layer of our
   distributed Public Key Infrastructure — PKI(d) protocol. In a nutshell, it’s
   a multi-purpose blockchain that acts as a distributed storage for a
   certificate’s hash, state (valid or revoked), public key and expiration date.
2. Based on your needs, define what kind of information (e.g. multi-signature)
   REMME digital certificate will contain.
3. Choose how to integrate REMME:

.. list-table::
   :header-rows: 1

   * - Library
     - Repository
     - Version
   * - REMME JS SDK
     - `remme-client-js <https://github.com/Remmeauth/remme-client-js>`_
     - |npm|
   * - REMME .NET SDK
     - `remme-client-dotnet <https://github.com/Remmeauth/remme-client-dotnet>`_
     - |nuget|

4. Use REMME Testnet to check your ideas.
5. Discuss your integration concept in `REMME tech community
   <https://gitter.im/REMME-Tech>`_ or call for help if you need it.

API endpoints for public testnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We are striving to simplify interaction with the REMchain by providing a common
RPC and WebSocket architecture and formatting. There are several endpoints
provided for managing the node and reading its state.

In order to start interacting with RPC API with an interface, you may need to
start the node locally and access the generated `RPC-API documentation
<https://docs.remme.io/remme-core/docs/rpc-api.html>`_.

- https://node-genesis-testnet.remme.io
- https://node-1-testnet.remme.io
- https://node-2-testnet.remme.io
- https://node-3-testnet.remme.io
- https://node-4-testnet.remme.io

Getting started with your own node
----------------------------------

The node was tested on Linux and macOS. Running on Windows may require
significant modification of startup scripts.

Currently it is not possible to connect your own node to the test network. All
nodes you will run will work on your own network.

Prerequisites
~~~~~~~~~~~~~

- `Docker Compose <https://docs.docker.com/compose/install/>`_ (17.09.0+)
- Docker (compatible with your Docker Compose)

For an end-user
~~~~~~~~~~~~~~~

#. Download the latest release from
   `Releases <https://github.com/Remmeauth/remme-core/releases>`_ section
   (``<version_number>-release.zip``). Unpack it.
#. Start node: Open a terminal inside the unpacked folder and run
   ``./run.sh``.
#. You can now use our RPC API. By default it is started on
   http://localhost:8080. The API port can be changed in
   ``config/network-config.env`` file.

On the first run you will need to initialize the genesis block. To make
that just run ``./run.sh -g``. This will generate a new key pair and
genesis block.

Flags available for ``run.sh`` are:

- ``scripts/run.sh`` features a single entrypoint to run a project with the
   following flags:
  
  - ``-g`` to run a node in genesis mode
  - ``-b`` to run a node in background
  - ``-u`` to start a node (default flag)
  - ``-d`` to stop a node

Ubuntu 16.04 and 18.04
~~~~~~~~~~~~~~~~~~~~~~

Open the terminal, using `this guide <https://askubuntu.com/a/183777>`_ and just copy and paste this huge command below.

.. code-block:: console

   $ export REMME_CORE_RELEASE=0.6.0-alpha && \
         sudo apt-get install apt-transport-https ca-certificates curl software-properties-common -y && \
         cd /home/ && curl -L https://github.com/Remmeauth/remme-core/archive/v$REMME_CORE_RELEASE.tar.gz | sudo tar zx && \
         cd remme-core-$REMME_CORE_RELEASE && \
         sudo apt update && sudo apt upgrade -y && \
         curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
         sudo apt update && \
         sudo apt install docker.io -y && \
         sudo curl -o /usr/local/bin/docker-compose -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" && \
         sudo chmod +x /usr/local/bin/docker-compose && \
         sudo ./scripts/run.sh -g

Or you can copy and paste it one by one. Some commands does not do response, so jump to the next one calmly if you do not see output.

.. code-block:: console

   $ export REMME_CORE_RELEASE=0.6.0-alpha
   $ sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
   $ cd /home/ && curl -L https://github.com/Remmeauth/remme-core/archive/v$REMME_CORE_RELEASE.tar.gz | sudo tar zx
   $ cd remme-core-$REMME_CORE_RELEASE
   $ sudo apt update && sudo apt upgrade -y
   $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
   $ sudo apt update
   $ sudo apt install docker.io -y 
   $ sudo curl -o /usr/local/bin/docker-compose -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)"
   $ sudo chmod +x /usr/local/bin/docker-compose
   $ sudo ./scripts/run.sh -g

To check if your node did setup correctly, send getting node configurations keys request.

.. code-block:: console

   $ export NODE_IP_ADDRESS=127.0.0.1
   $ curl -X POST http://$NODE_IP_ADDRESS:8080 -H 'Content-Type: application/json' -d \
         '{"jsonrpc":"2.0","id":"11","method":"get_node_config","params":{}}' | python -m json.tool

Response should be similar.


.. code-block:: console

   $ {
       "id": "11",
       "jsonrpc": "2.0",
       "result": {
         "node_public_key": "028e7e9b060d7c407e428676299ced9afef4ce782995294d8ea01fd0f08cec9765",
         "storage_public_key": "028e7e9b060d7c407e428676299ced9afef4ce782995294d8ea01fd0f08cec9765"
       }
     }

Cloud computing services or virtual private servers (VPS)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Digital Ocean** — cloud services that help to deploy and scale applications that run simultaneously on multiple computers. Digital Ocean optimized configuration process saves your team time when running and scaling distributed applications, AI & machine learning workloads, hosted services, client websites, or CI/CD environments. 

**References**:

1. Digital Ocean website — `https://www.digitalocean.com <https://www.digitalocean.com>`_.

.. image:: https://habrastorage.org/webt/fo/r9/lf/for9lfnp3fvh7m7ktspq2-vq_4o.png
.. image:: https://habrastorage.org/webt/v1/br/aa/v1braanm3or87lcykngp785fkcc.png
.. image:: https://habrastorage.org/webt/so/07/dp/so07dpb_rv0ixxt8pxmo16hmrhu.png
.. image:: https://habrastorage.org/webt/to/jr/hf/tojrhfuv6rvjf5aaxgnbuapnf88.png
.. image:: https://habrastorage.org/webt/ez/io/lu/ezioluea_9svree-lx27gxaoyce.png

.. image:: https://habrastorage.org/webt/g3/ee/eu/g3eeeu3tf0vesfjjsf_rw2hi5ii.png
.. image:: https://habrastorage.org/webt/l3/8_/vo/l38_vog1qxel1dhuxvtwdyshzek.png

.. image:: https://habrastorage.org/webt/u5/oc/g5/u5ocg5gt4qblk6fjd1xr4hbyeh0.png
.. image:: https://habrastorage.org/webt/bh/hg/cu/bhhgcufnr5ynqmcgogqyaz2mxyo.png
.. image:: https://habrastorage.org/webt/jm/0k/c_/jm0kc_7-6cu88-8hbeapqkysyjg.png
.. image:: https://habrastorage.org/webt/4p/y2/kb/4py2kbgzp7o1btb2dbmqownt0aa.png

.. image:: https://habrastorage.org/webt/fp/rv/qd/fprvqd3nk6us1qauax-v_ct_lfe.png
.. image:: https://habrastorage.org/webt/od/eq/05/odeq0563fgdrn7chqwzb4qmeije.png

.. image:: https://habrastorage.org/webt/fz/go/i2/fzgoi2xsajoxzdxmm8tvve0kke4.png



.. image:: https://habrastorage.org/webt/y8/mk/-5/y8mk-5ukwhyrs0pgsntoxuoy4tw.png
.. image:: https://habrastorage.org/webt/tm/je/i1/tmjei1awx38asdxzcx8iqmzfbik.png

.. image:: https://habrastorage.org/webt/fp/d3/kj/fpd3kjvzx5pvvg2mffsujgspg4m.png



Digital Ocean
~~~~~~~~~~~~~

If you a bit fimilar with cloud services and/or `virtual private servers <https://en.wikipedia.org/wiki/Virtual_private_server>`_ (VPS), have payment card with $5 per month to rent the one and want to publish ``Remme-core`` on the Internet to share it with friends, follow the steps below:

1. `Create Digital Ocean account <https://cloud.digitalocean.com/registrations/new>`_.
2. `Create droplet (server) <https://www.digitalocean.com/docs/droplets/how-to/create/>`_ to locate the node on, choose any version of Ubuntu destribution we have guide above.
3. Take a look at your e-mail box to find your new server details.

.. image:: https://habrastorage.org/webt/v9/dt/ni/v9dtni9i-hrx3bvfy69xchqabvo.png

4. Open the terminal, using this guide for `Ubuntu <https://askubuntu.com/a/183777>`_ or this for `MacOS <https://blog.teamtreehouse.com/introduction-to-the-mac-os-x-command-line>`_.
5. Then connect to the server by IP-address from the mail (change in examples below) and type ``yes`` to verify you want to continue the connection.

.. code-block:: console

    $ ssh root@157.230.129.118
    $ The authenticity of host '157.230.129.118 (157.230.129.118)' can't be established.
      ECDSA key fingerprint is SHA256:AJnmHx1DeCDFCBddVxZmTt64H7WPxykoCsa0ZTCcUnY.
      Are you sure you want to continue connecting (yes/no)? yes
      
6. Type password from the mail while connection and while requesting it again (``(current) UNIX password``). Attention, when you copy paste password or type it manually, it will be hidden from your eye, so just paste and press ``Enter``.

.. code-block:: console

    $ root@157.230.129.118's password: 
      ...
      Changing password for root.
      (current) UNIX password:
    
7. Create brand new password due to the security reasons and you are almost ready!

.. code-block:: console

    $ ...
      Enter new UNIX password:
      Retype new UNIX password:

8. Copy paste commands from the section about where we explained how to install the run the node on Ubuntu 16.04 and 18.04. If while installation on server you get the same screen, just press enter key to keep instalation on.

.. image:: https://habrastorage.org/webt/fz/go/i2/fzgoi2xsajoxzdxmm8tvve0kke4.png

10. Check node did setup correctly, send getting node configurations keys, changing `127.0.0.1` to the the IP address from mail.

For developers & contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clone this repository to your machine:
``git clone https://github.com/Remmeauth/remme-core.git``

When you have this repository cloned go the project directory and run

#. ``make build_dev`` (``make build`` for more compact but slower builds)
#. ``make run_genesis`` or ``make run`` if you are working on an existing chain.

**NOTE:** on further runs you might want to run ``make run`` to persist the
transaction created before. If you want to start with a clean chain, use ``make
run_genesis`` again.

You can run ``make test`` to run automated tests.

Building documentation
----------------------

Prerequesites for building the documentation are ``sphinx`` and
``sphinx_rtd_theme``. You can build the documentation with ``make docs``
command.

License
-------

REMME software and documentation are licensed under `Apache License Version 2.0
<LICENCE>`_.

.. |Docker Stars| image:: https://img.shields.io/docker/stars/remme/remme-core.svg
   :target: https://hub.docker.com/r/remme/remme-core/
.. |Gitter| image:: https://badges.gitter.im/owner/repo.png
   :target: https://gitter.im/REMME-Tech
.. |npm| image:: https://img.shields.io/npm/v/remme.svg
   :target: https://www.npmjs.com/package/remme
.. |nuget| image:: https://img.shields.io/nuget/v/REMME.Auth.Client.svg
   :target: https://www.nuget.org/packages/REMME.Auth.Client/
.. |Jenkins| image:: https://jenkins.remme.io/buildStatus/icon?job=remme-core/dev
   :target: https://jenkins.remme.io/view/1.GitHub_Integration/job/remme-core/job/dev/
