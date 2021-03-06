*****
Vultr
*****

**Vultr**, founded in 2014, is on a mission to empower developers and businesses by simplifying the deployment of
infrastructure via its advanced cloud platform. **Vultr** is strategically located in 16 datacenters around the globe
and provides frictionless provisioning of public cloud, storage and single-tenant bare metal.

Step 1: sign up
===============

Visit the |registration_link| to create your own account on ``Vultr``.

.. |registration_link| raw:: html

   <a href="https://www.vultr.com/register/" target="_blank">registration link</a>

.. image:: /img/user-guide/cloud/vultr/sign-up-form.png
   :width: 100%
   :align: center
   :alt: Sign up form

Open your inbox, select the confirmation letter from ``Vultr`` and click on the link.

.. image:: /img/user-guide/cloud/vultr/confirm-e-mail-link.png
   :width: 100%
   :align: center
   :alt: Confirm e-mail ling

Enter your credit/debit card details into the form to pay for cloud services. You also have several payment options such
as ``PayPal`` and ``Bitcoin``.

.. image:: /img/user-guide/cloud/vultr/credit-card-form.png
   :width: 100%
   :align: center
   :alt: Credit or debit card details

Step 2: first server
=====================

After adding the payment method you will be redirected to the service creation page.

Choose any location you want - it does not matter. A node will be connected to the nearest other nodes in the region.

.. image:: /img/user-guide/cloud/vultr/server-location.png
   :width: 100%
   :align: center
   :alt: Server location

Specify server type ``Ubuntu 16.04 x64``, which should be regarded as an operating system, and choose the size of memory and
processor power for ``$20 per month``.

.. image:: /img/user-guide/cloud/vultr/server-type-and-size.png
   :width: 100%
   :align: center
   :alt: Server type and size

We also recommend enabling backups to revert the server in case you occasionally do something wrong. In the additional
feature list, tick the checkbox ``Enable Auto Backups`` to activate server backups.

Then generate your personal ``SSH key`` and add it to the server. Visit the :doc:`/user-guide/troubleshooting` section to
find information about your ``SSH key`` and instructions on how to generate it.

An example of your ``SSH key`` and how to add it to the droplet is illustrated in the image below.

.. image:: /img/user-guide/cloud/vultr/server-ssh-key-adding.png
   :width: 100%
   :align: center
   :alt: Droplet SSH key adding

Remember to click on the created ``SSH key`` to activate it. Below, specify the name of the server you wish to connect
to (e.g. ``remme-core-testnet-node``) and press ``Deploy Now``.

.. image:: /img/user-guide/cloud/vultr/server-hostname-and-start.png
   :width: 100%
   :align: center
   :alt: Server hostname and start

Wait for your server to be ready as illustrated on the image below.

.. image:: /img/user-guide/cloud/vultr/server-is-ready.png
   :width: 100%
   :align: center
   :alt: Server is ready

Step 3: login to server
=======================

Open a terminal on your PC. Visit the :doc:`/user-guide/troubleshooting` section to find instructions how to do this.

With ``SSH key`` you will be able to authenticate yourself with the password from the ``SSH key``, as illustrated below.
Type ``root@157.230.146.230``, but instead of ``157.230.146.230``, put your server's ``IP address``.
When you see the output line ``Enter passphrase for key ...``, enter the password from the ``SSH key``. Mind that when you
do it the password doesn't appear – even stars or bullets shouldn’t appear as you wait to login to the account on the
operating system. So enter and press ``Enter``.

.. image:: /img/user-guide/cloud/vultr/login-to-the-server-ssh.png
   :width: 100%
   :align: center
   :alt: Droplet SSH key login

Step 4: start the project
=========================

Copy commands below and paste it into the terminal. You can change the value of ``REMME_CORE_RELEASE`` below, just take
a look at our `release list <https://github.com/Remmeauth/remme-core/releases>`_. We would recommend the latest version of
the project that already specified in the command below.

.. code-block:: console

   $ export REMME_CORE_RELEASE=0.7.0-alpha
   $ sudo apt-get install apt-transport-https ca-certificates curl software-properties-common make -y && \
         cd /home/ && curl -L https://github.com/Remmeauth/remme-core/archive/v$REMME_CORE_RELEASE.tar.gz | sudo tar zx && \
         cd remme-core-$REMME_CORE_RELEASE && \
         sudo apt update && sudo apt upgrade -y && \
         curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
         sudo apt update && \
         sudo apt install docker.io -y && \
         sudo curl -o /usr/local/bin/docker-compose -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" && \
         sudo chmod +x /usr/local/bin/docker-compose && \
         sudo make run_genesis_bg

.. image:: /img/user-guide/cloud/digital-ocean/installation-command.png
   :width: 100%
   :align: center
   :alt: Terminal installation command example

The expected result of this command is illustrated below.

.. image:: /img/user-guide/cloud/digital-ocean/installation-output.png
   :width: 100%
   :align: center
   :alt: Installation output

If during installation the same window as illustrated below appears, just press ``Enter``.

.. image:: /img/user-guide/cloud/digital-ocean/installation-possible-window.png
   :width: 100%
   :align: center
   :alt: Installation possible window

When you see the same output as illustrated below, it means the node is ready to accept requests.

.. image:: /img/user-guide/cloud/digital-ocean/proof-core-is-up.png
   :width: 100%
   :align: center
   :alt: Proof core is up

To check if your node has completed a correct setup, open a brand new terminal window and send a request to get node configurations.
If you use ``Windows``, change word ``export`` to ``set`` and install (download an archive and open it) |curl_tool| to send a request the node. Remember to change ``157.230.146.230`` to your server ``IP address``.

.. |curl_tool| raw:: html

   <a href="https://curl.haxx.se/download.html" target="_blank">tool named curl </a>

.. code-block:: console

   $ export NODE_IP_ADDRESS=95.179.156.74
   $ curl -X POST http://$NODE_IP_ADDRESS:8080 -H 'Content-Type: application/json' -d \
         '{"jsonrpc":"2.0","id":"11","method":"get_node_config","params":{}}' | python -m json.tool

The response should look similar to this:

.. code-block:: console

   {
       "id": "11",
       "jsonrpc": "2.0",
       "result": {
           "node_public_key": "028e7e9b060d7c407e428676299ced9afef4ce782995294d8ea01fd0f08cec9765"
       }
   }

The flow is illustrated below.

.. image:: /img/user-guide/cloud/digital-ocean/proof-core-is-working.png
   :width: 100%
   :align: center
   :alt: Proof core is working

What's next?
============

1. Secure your account with two-factor authentication that adds an extra layer of security to your account. To log in, you'll
need to provide a code along with your username and password.

.. image:: /img/user-guide/cloud/vultr/2-fa-authentication.png
   :width: 100%
   :align: center
   :alt: 2FA authentication

2. Set up desirable backup settings.

.. image:: /img/user-guide/cloud/vultr/server-backups.png
   :width: 100%
   :align: center
   :alt: Server type and size

3. Take a look at the server's monitoring at the ``User graph`` menu section. There are graphs which illustrate performance metrics.

.. image:: /img/user-guide/cloud/vultr/server-monitoring.png
   :width: 100%
   :align: center
   :alt: Server type and size

4. Visit our :doc:`/user-guide/advanced-guide` for more details on user experience.
5. Communication with the node is available through :doc:`/apis/rpc` API, so check it out.
