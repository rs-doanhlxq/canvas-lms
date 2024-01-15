#!/usr/bin/env bash
# exit on error
set -o errexit
wget http://security.ubuntu.com/ubuntu/pool/main/libx/libxml-security-c/libxmlsec1-dev_1.2.20-2ubuntu4.2_amd64.deb
dpkg -x libxmlsec1-dev_1.2.20-2ubuntu4.2_amd64.deb ~/custom_libxmlsec1
bundle config build.nokogiri --use-system-libraries --with-xml2-include=$HOME/custom_libxmlsec1/include/libxml2

bundle config set force_ruby_platform true # https://stackoverflow.com/a/66311533
bundle install
./bin/rails assets:precompile
./bin/rails assets:clean
