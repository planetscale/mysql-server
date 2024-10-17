--disable_query_log
--disable_result_log
--let $scan_count=10

# Run some (round robin) scans to ensure normal number
# of seized api connect records
while ($scan_count)
{
  select * from test.t1;
  --dec $scan_count
}

# 7.6 only
--exec $NDB_MGM -e "ALL DUMP 2559 1"
# Count TC ApiConnectRecords not in states
#   1 (CS_DISCONNECTED)
#   7 (CS_RESTART)
select count(1) into @acc_count from ndbinfo.ndb$transactions where state != 7 and state != 1;

let $api_conn_count=query_get_value(select @acc_count as acc, acc, 1);

--exec $NDB_MGM -e "ALL DUMP 2559 0"
--enable_result_log
--enable_query_log
