if node[:platform_family] == 'fedora'
  package 'redhat-lsb'  #TODO: Is that installed on Red Hat already?
end

daemons = [
  {:daemon_name => 'msgsender', :daemon_module => 'msg_sender', :daemon_desc => 'Scalr Messaging Daemon', :daemon_extra_args => '' },
  {:daemon_name => 'dbqueue', :daemon_module => 'dbqueue_event', :daemon_desc => 'Scalr DB Queue Event Poller', :daemon_extra_args => '' },
  {:daemon_name => 'plotter', :daemon_module => 'load_statistics', :daemon_desc => 'Scalr Load Stats Plotter', :daemon_extra_args => '--plotter' },
  {:daemon_name => 'poller', :daemon_module => 'load_statistics', :daemon_desc => 'Scalr Load Stats Poller', :daemon_extra_args => '--poller' },
]

daemons.each do |daemon|
  args = daemon.clone
  args[:executable] = "/usr/bin/python" # TODO: Dynamic?
  args[:piddir] = node[:scalr][:core][:pid_dir]
  args[:pidfile] = "#{args[:piddir]}/#{args[:daemon_name]}.pid"
  args[:logfile] = "#{node[:scalr][:core][:log_dir]}/#{args[:daemon_name]}.log"
  args[:user] = node[:scalr][:core][:users][:service]
  args[:group] = node[:scalr][:core][:group]

  init_file = "/etc/init.d/#{args[:daemon_name]}"

  template init_file do
    source "#{node[:platform_family]}-init-service.erb"
    mode 0755
    owner "root"
    group "root"
    variables args
  end

  service daemon[:daemon_name] do
    subscribes :restart, "template[#{init_file}]", :delayed
    subscribes :restart, "template[#{node[:scalr][:core][:configuration]}]", :delayed
    subscribes :restart, "execute[Mark Install]", :delayed
    subscribes :restart, "ruby_block[Set Endpoint Hostname]", :delayed
    subscribes :restart, "artifact_deploy[#{node[:scalr][:core][:package][:name]}]", :delayed
    action value_for_platform_family(['rhel', 'fedora'] => :enable, 'debian' => :nothing)
  end
end
