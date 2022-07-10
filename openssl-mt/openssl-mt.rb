#!/usr/bin/env ruby
BEGIN {
  $cr = Hash.new(0); $cr.default = 0;
}
ec_curves = %w[secp160r1 nistp192 nistp224 nistp256 nistp384 nistp521 nistk163 nistk233 nistk283 nistk409 nistk571 nistb163 nistb233 nistb283 nistb409 nistb571 brainpoolP256r1 brainpoolP256t1 brainpoolP384r1 brainpoolP384t1 brainpoolP512r1 brainpoolP512t1 X25519 X448]
while gets
  begin
    $cr["rsa-#{$3}-sign"] += $4.to_f
    $cr["rsa-#{$3}-verify"] += $5.to_f
    next
  end if $_ =~ /^Got:\s+(\+F2):(\d+):(\d+):([^:]+):([^ ]+)/
  begin
    $cr["dsa-#{$3}-sign"] += $4.to_f
    $cr["dsa-#{$3}-verify"] += $5.to_f
    next
  end if $_ =~ /^Got:\s+(\+F3):(\d+):(\d+):([^:]+):([^ ]+)/
  begin
    $cr["ecdsa-#{ec_curves[$2.to_i]}-sign"] += $4.to_f
    $cr["ecdsa-#{ec_curves[$2.to_i]}-verify"] += $5.to_f
    next
  end if $_ =~ /^Got:\s+(\+F4):(\d+):(\d+):([^:]+):([^ ]+)/
  begin
    $cr["ecdh-#{ec_curves[$2.to_i]}"] += $4.to_f
    next
  end if $_ =~ /^Got:\s+(\+F5):(\d+):(\d+):([^:]+):([^ ]+)/
  begin
    $cr["eddsa-#{$4}-sign"] += $5.to_f
    $cr["eddsa-#{$4}-verify"] += $6.to_f
    next
  end if $_ =~ /^Got:\s+(\+F6):(\d+):(\d+):([^:]+):([^:]+):([^ ]+)/
  begin
    $cr["sm2-#{$4}-sign"] += $5.to_f
    $cr["sm2-#{$4}-verify"] += $6.to_f
    next
  end if $_ =~ /^Got:\s+(\+F7):(\d+):(\d+):([^:]+):([^:]+):([^ ]+)/
  begin
    $cr["ffdh-#{$3}"] += $4.to_f
    next
  end if $_ =~ /^Got:\s+(\+F8):(\d+):(\d+):([^:]+):([^ ]+)/
  begin
    # symmetrical, hashes and hmacs, sizes: 16,64,256,1024,8*1024, 16*1024
    $cr["#{$3}-16"] += $4.to_f
    $cr["#{$3}-64"] += $5.to_f
    $cr["#{$3}-256"] += $6.to_f
    $cr["#{$3}-1024"] += $7.to_f
    $cr["#{$3}-8192"] += $8.to_f
    $cr["#{$3}-16384"] += $9.to_f
    next
  end if $_ =~ /^Got:\s+(\+F):(\d+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^: ]+)/
  unless ($_ =~ /^Forked child/ or $_ =~ /^Got: \+H:/)
    # unknown lines
    STDERR.puts $_
  end
end

END{
  ENV["OUT_FORMAT"] = "bench"
  if (ENV["OUT_FORMAT"]&.downcase == "json")
    require 'json'
    puts JSON.generate($cr)
  elsif (ENV["OUT_FORMAT"]&.downcase == "bench")

    # results in 1000s ?
    print [$cr["md5-1024"], $cr["sha1-1024"], $cr["sha256-1024"], $cr["sha512-1024"], $cr["des-1024"], $cr["des-ede3-8192"],
           $cr["aes-128-cbc-8192"], $cr["aes-192-cbc-8192"], $cr["aes-256-cbc-8192"]].map { |x| x.round() }.join(" | ")
    print " | "
    print ([$cr["rsa-2048-sign"], $cr["rsa-2048-verify"], $cr["dsa-2048-sign"], $cr["dsa-2048-verify"]].map { |x| x.round(1) }.join(" | "))
    puts " | "
  else
    $cr.each { |k, v| printf "%-30s %20.2f\n", k, v }
  end
}
