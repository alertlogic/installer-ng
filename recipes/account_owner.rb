require 'digest'

#TODO: There's a bit of copy-paste going on here!
mysql_conn_params = "-h'#{node[:scalr][:database][:host]}' -u'#{node[:scalr][:database][:username]}' -p'#{node[:scalr][:database][:password]}' -D'#{node[:scalr][:database][:dbname]}'"

h = Digest::SHA256.new
h.update node[:scalr][:account_owner][:password]

owner_id = 2
account_id = 1

execute "Add account info" do
  command "mysql #{mysql_conn_params} -e \"INSERT INTO clients(id, name, status) VALUES (#{account_id}, 'Default Account', 'Active')\""
  not_if "mysql #{mysql_conn_params} -e \"SELECT id FROM clients WHERE id=#{account_id}\" | grep #{account_id}"  # Data from Scalr 4.5.1
end

execute "Add account owner record" do
  command "mysql #{mysql_conn_params} -e \"INSERT INTO account_users(id, account_id, status, email, type) VALUES (#{owner_id}, #{account_id}, 'Active', '#{node[:scalr][:account_owner][:username]}', 'AccountOwner')\""
  not_if "mysql #{mysql_conn_params} -e \"SELECT id FROM account_users WHERE id=#{owner_id}\" | grep #{owner_id}"  # Data from Scalr 4.5.1
end

execute "Set Account Owner Username" do
  command "mysql #{mysql_conn_params} -e \"UPDATE account_users SET email='#{node[:scalr][:account_owner][:username]}' WHERE id=#{owner_id}\""
  not_if "mysql #{mysql_conn_params} -e \"SELECT id FROM account_users WHERE id=#{owner_id} AND email='#{node[:scalr][:account_owner][:username]}'\" | grep #{owner_id}"  # Data from Scalr 4.5.1
end

execute "Set Account Owner Password" do
  command "mysql #{mysql_conn_params} -e \"UPDATE account_users SET password='#{h.hexdigest}' WHERE id=#{owner_id}\""
  not_if "mysql #{mysql_conn_params} -e \"SELECT id FROM account_users WHERE id=#{owner_id} AND password='#{h.hexdigest}'\" | grep #{owner_id}"  # Data from Scalr 4.5.1
end

