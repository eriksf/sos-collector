# sos-collector
**Note:** sos-collector is still under development and is not yet functional.
This note will be removed when sos-collector has been completed. 

---
Collect sosreport across distributed environments with one simple tool.

sos-collector is a tool intended for capturing sosreports on a selection of
hosts.  Even though tools such as Ansible exist which can perform this task,
the goal of this project is to provide a way to collect multiple sosreports
without the need for outside tooling.

## Installation
* Install `python-pip` on your desired distro.
* Run the provided `setup.py` file to install the required libraries

~~~
./setup.py install
~~~

## Usage
The beauty of sos-collector is that you only need to run it from one machine
to grab sosreports from many different hosts at once.  The resulting sosreport
tarballs will be captured and archived into one large tarball on the host
where sos-collector is ran.

There are two main ways for running sos-collector:
* By specifying hosts on the command line, comma-delimited using the `--hosts, -H`
flag.  

If using this option, all hosts must have identical root passwords **or**
keyless SSH must already be configured.  If keyless SSH is already configured,
provide the `--no-root` flag to disable initial keyless SSH configuration.

~~~
./sos-collector.py -H hostname.example.com,hostname2.example.com [--no-root]
~~~

* By specifying hosts in a provided host-file using the following format:

~~~
hostname.example.com::rootpassword
hostname2.example.com::rootpassword2
~~~

then specifying the host-file with the `--host-file, -f` flag:

~~~
./sos-collector.py -f /example/hostfile
~~~
