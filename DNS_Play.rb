##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

require 'resolv'
require 'securerandom'

require 'rubygems'
require 'whois'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  #  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
          'Name'        => 'Metasploit DNS poke',
          'Description' => 'This module checks out the DNS values for a domain.',
          'Author'       => ['Del Armstrong'],
          'License'     => MSF_LICENSE
          )

    register_options(
                     [
                      OptString.new('DOMAIN', [ true,  "Domain to explore", '']),
                     ], self.class)

  end


  def run

    begin
      print_status("Checking common domains for #{datastore['DOMAIN']}")

      b = BruteForce.new

      #
      # Handle wildcard check first
      #

      wildcard = b.check_for_wildcard(datastore['DOMAIN'])
      if wildcard != ""
        begin
          wildcard_name = Resolv.getnames("#{wildcard}")
        rescue
          wildcard_name = "** No reverse DNS **"
        end
        print_status ("Wildcard response detected.\n  <Any hostname>.#{datastore['DOMAIN']} resolves to: #{wildcard} (#{wildcard_name})")
      end

      #
      # Now list all the common hostnames which resolve
      #

      result = b.dns(datastore['DOMAIN'])

      printed_a_hostname = false  # Track whether any non-wildcard hostnames have been printed
      result.sort.each { |key, value|    # Note: sort in order to list 'like' subnets together, not to "sort" them
        unless key == wildcard
          unless printed_a_hostname
            print_status "The following \'common\' hostnames were found (excluding any wildcards):"
            printed_a_hostname = true
          end
          print_status ("#{key}\t#{value}") 
        end
      }

      #
      # Now list any host with a reverse in any of the networks we've already seen
      #

      print_status ("Other hostnames on discovered networks:")
      result.each { |existing_ip, existing_hostname|

        discovered_hosts = b.list_subnet(existing_ip)
        subnet = existing_ip[/^\d+\.\d+\.\d+/]
        unless discovered_hosts.empty?
          print_status "Found on #{subnet}.*:"
        else
          print_status "  #{subnet}.* has no reverse DNS entries"
        end
        discovered_hosts.each { |discovered_address, discovered_hostname|
          print_status ("  #{discovered_address} - #{discovered_hostname}")
        }
      }

      #
      # Now dump whois info
      #

      whois_report = b.show_whois ("#{datastore['DOMAIN']}")

      print_status "Whois report for #{datastore['DOMAIN']}"
      print_status "#{whois_report}"

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end

class BruteForce

  def wordlist
    # Note, this method will just return an array
    begin
      File.read("words.txt").split("\n")
    rescue
      ['www', 'blog', 'mail', 'smtp', 'pop']
    end
  end


  def dns (domain)

    #
    # check for hostnames from wordlist
    #
    
    address_list = nil
    address_hash = Hash.new

    wordlist.each do |word|
      if word.length > 0
        name = "#{word}.#{domain}"
      else             # In case we have a null host e.g. just google.com
        name = "#{domain}"
      end

      begin
        address_list = Resolv.getaddresses(name)
      rescue Resolv::ResolvError => e
        #        puts "#{name} did not resolve: e.message"
      end

      address_list.each do |address|
        address_hash[address] = name
      end

    end
    address_hash
  end

  def check_for_wildcard(domain)

    # test.com will exhibit this behavior

    begin
      random_host = SecureRandom.hex(5)
      address = Resolv.getaddress("#{random_host}.#{domain}")
      address
    rescue Resolv::ResolvError => e
      ""
    end

  end

  def list_subnet (address)

    # list all hosts in a class-C which have a DNS reverse

    sh_test = defined? @subnet_hash

    response = Hash.new
    if (defined? @subnet_hash) == nil
      @subnet_hash = Hash.new
    end

    subnet = address[/^\d+\.\d+\.\d+/]

    if @subnet_hash[subnet]    # Don't repeat a subnet we've already seen
    else
      (0..254).each do |host|
        checking = "#{subnet}.#{host}"
        begin
          name = Resolv.getname("#{checking}")
          response["#{checking}"] = name
        rescue Resolv::ResolvError => e
          #          puts " Resolv.getname(#{checking}) failed, error = #{e.message}, name = #{name}"
        end
      end
      @subnet_hash[subnet] = true   # We've done this one
    end
    response
  end

  def show_whois (whois_target)

    begin
      whois_response = Whois.query("#{whois_target}")
    rescue Whois::Error => e
      return "--> Whois Failed (Whois:: Eror): #{e.message}"
    rescue StandardError => e
      return "--> Whois Failed (Standard Error): #{e.message}"
    end

    response = ""
    response_is_nil = true

    unless whois_response.admin_contact.nil?
      response << "Admin Contact:\n"
      response << "   #{whois_response.admin_contact.name}\n" unless whois_response.admin_contact.name == nil
      response << "   #{whois_response.admin_contact.organization}\n" unless whois_response.admin_contact.organization == nil
      response << "   #{whois_response.admin_contact.address}\n" unless whois_response.admin_contact.address == nil
      response << "   #{whois_response.admin_contact.city}\n" unless whois_response.admin_contact.city == nil
      response << "   #{whois_response.admin_contact.state}\n" unless whois_response.admin_contact.state == nil
      response << "   #{whois_response.admin_contact.zip}\n" unless whois_response.admin_contact.zip == nil
      response << "   #{whois_response.admin_contact.country_code}\n" unless whois_response.admin_contact.country_code == nil
      response << "   #{whois_response.admin_contact.email}\n\n" unless whois_response.admin_contact.email == nil
      response_is_nil = false
    end

    unless whois_response.technical_contact.nil?
      response << "Technical Contact:\n"
      response << "   #{whois_response.technical_contact.name}\n" unless whois_response.technical_contact.name == nil
      response << "   #{whois_response.technical_contact.organization}\n" unless whois_response.technical_contact.organization == nil
      response << "   #{whois_response.technical_contact.address}\n" unless whois_response.technical_contact.address == nil
      response << "   #{whois_response.technical_contact.city}\n" unless whois_response.technical_contact.city == nil
      response << "   #{whois_response.technical_contact.state}\n" unless whois_response.technical_contact.state == nil
      response << "   #{whois_response.technical_contact.zip}\n" unless whois_response.technical_contact.zip == nil
      response << "   #{whois_response.technical_contact.country_code}\n" unless whois_response.technical_contact.country_code == nil
      response << "   #{whois_response.technical_contact.email}\n\n" unless whois_response.technical_contact.email == nil
      response_is_nil = false
    end

    unless whois_response.registrant_contact.nil?
      response << "Registrant Contact:\n"
      response << "   #{whois_response.registrant_contact.name}\n" unless whois_response.registrant_contact.name == nil
      response << "   #{whois_response.registrant_contact.organization}\n" unless whois_response.registrant_contact.organization == nil
      response << "   #{whois_response.registrant_contact.address}\n" unless whois_response.registrant_contact.address == nil
      response << "   #{whois_response.registrant_contact.city}\n" unless whois_response.registrant_contact.city == nil
      response << "   #{whois_response.registrant_contact.state}\n" unless whois_response.registrant_contact.state == nil
      response << "   #{whois_response.registrant_contact.zip}\n" unless whois_response.registrant_contact.zip == nil
      response << "   #{whois_response.registrant_contact.country_code}\n" unless whois_response.registrant_contact.country_code == nil
      response << "   #{whois_response.registrant_contact.email}\n\n" unless whois_response.registrant_contact.email == nil
      response_is_nil = false
    end

    unless whois_response.registrar.nil?
      response << "Registrar:\n"
      response << "   #{whois_response.registrar.id}\n" unless whois_response.registrar.id == nil
      response << "   #{whois_response.registrar.name}\n" unless whois_response.registrar.name == nil
      response << "   #{whois_response.registrar.organization}\n" unless whois_response.registrar.organization == nil
      response << "   #{whois_response.registrar.url}\n\n" unless whois_response.registrar.url == nil
    end

    unless whois_response.server.nil?
      response << "Server: #{whois_response.server.host}\n"
    end

    unless whois_response.nameservers.nil?
      whois_response.nameservers.each do |nameserver|
        response << "Name Server: #{nameserver.name}\t#{nameserver.ipv4}\t#{nameserver.ipv6}\n"
      end
    end

    unless whois_response.status.nil?
      response << "Status:\n"
      if whois_response.status.class == Array 
        whois_response.status.each do |status|
          response << "   #{status}\n"
        end
      else
          response << "   #{whois_response.status}\n"
      end
    end

    unless whois_response.created_on.nil?
      response << "Created on: #{whois_response.created_on}\n"
    end

    unless whois_response.updated_on.nil?
      response << "Updated on: #{whois_response.updated_on}\n"
    end

    unless whois_response.expires_on.nil?
      response << "Expires on: #{whois_response.expires_on}\n"
    end

    unless whois_response.available?.nil?
      response << "Available: #{whois_response.available?}\n"
    end

    unless whois_response.registered?.nil?
      response << "Registered: #{whois_response.registered?}\n"
    end

    unless whois_response.domain.nil?
      response << "Domain: #{whois_response.domain}\n"
    end

    if response_is_nil    # Just dump the body if Whois was unable to parse
      response << "Unformatted Response:\n"
      response << whois_response.to_s
    end
    
    response
  end



end


