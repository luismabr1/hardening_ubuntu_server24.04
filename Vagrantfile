Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: true }
  config.vm.provider "virtualbox" do |v|
    v.default_nic_type = "Am79C973"
    v.memory = 2048
    v.cpus = 2
    v.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    v.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  config.vm.define "focal" do |focal|
    focal.ssh.extra_args = ["-o","ConnectTimeout=600"]
    focal.ssh.insert_key = true
    focal.vm.boot_timeout = 600
    focal.vm.box = "ubuntu/focal64"
    focal.vm.hostname = "focal"
  end

  config.vm.define "jammy" do |jammy|
    jammy.ssh.extra_args = ["-o","ConnectTimeout=600"]
    jammy.ssh.insert_key = true
    jammy.vm.boot_timeout = 600
    jammy.vm.box = "ubuntu/jammy64"
    jammy.vm.hostname = "jammy"
  end

  config.vm.define "lunar" do |lunar|
    lunar.ssh.extra_args = ["-o","ConnectTimeout=600"]
    lunar.ssh.insert_key = true
    lunar.vm.boot_timeout = 600
    lunar.vm.box = "lunar/20230222"
    lunar.vm.box_url = "https://cloud-images.ubuntu.com/lunar/20230222/lunar-server-cloudimg-amd64-vagrant.box"
    lunar.vm.box_download_checksum_type = "sha256"
    lunar.vm.box_download_checksum = "766970c1585d624ac9e2b7420f2675cc25cd387250d8ac04fb6b7ebc2cff7d25"
    lunar.vm.hostname = "lunar"
  end
end
