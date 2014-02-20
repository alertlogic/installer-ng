#TODO: Reduce duplication user
php = '/usr/bin/php -q'
cmd = "#{php} #{node[:scalr][:core][:location]}/app/cron/cron.php"
ng_cmd = "#{php} #{node[:scalr][:core][:location]}/app/cron-ng/cron.php"

cron "Scheduler" do
  user node[:scalr][:core][:users][:service]
  command "#{cmd} --Scheduler"
end

cron "UsageStatsPoller" do
  user node[:scalr][:core][:users][:service]
  minute "*/5"
  command "#{cmd} --UsageStatsPoller"
end

cron "Scaling" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{ng_cmd} --Scaling"
end

cron "SzrMessaging" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{cmd} --SzrMessaging --piddir #{node[:scalr][:core][:pid_dir]}"
end

cron "BundleTasksManager" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{cmd} --BundleTasksManager"
end

cron "MetricCheck" do
  user node[:scalr][:core][:users][:service]
  minute "*/15"
  command "#{ng_cmd} --MetricCheck"
end

cron "Poller" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{ng_cmd} --Poller"
end

cron "DNSManagerPoll" do
  user node[:scalr][:core][:users][:service]
  command "#{cmd} --DNSManagerPoll"
end

cron "RotateLogs" do
  user node[:scalr][:core][:users][:service]
  minute "17"
  hour "5"
  command "#{cmd} --RotateLogs"
end

cron "EBSManager" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{cmd} --EBSManager"
end

cron "RolesQueue" do
  user node[:scalr][:core][:users][:service]
  minute "*/20"
  command "#{cmd} --RolesQueue"
end

cron "DbMsrMaintenance" do
  user node[:scalr][:core][:users][:service]
  minute "*/5"
  command "#{ng_cmd} --DbMsrMaintenance"
end

cron "LeaseManager" do
  user node[:scalr][:core][:users][:service]
  minute "*/20"
  command "#{ng_cmd} --LeaseManager"
end

cron "ServerTerminate" do
  user node[:scalr][:core][:users][:service]
  minute "*/1"
  command "#{ng_cmd} --ServerTerminate"
end
