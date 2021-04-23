Vagrant.configure(2) do |config|
  config.vm.box = "kalilinux/rolling"

  config.vm.define 'kali' do |kali|
    kali.vm.hostname = 'kali'
    config.vm.network "public_network"

    kali.vm.provider :virtualbox do |vm|
      vm.gui = true
      vm.customize [
        "modifyvm", :id,
        "--memory", 4096,
        "--cpus", "2"
      ]
    end
  end
end
