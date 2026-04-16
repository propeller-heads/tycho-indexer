CALL partman.partition_data_proc(p_parent_table := 'public.protocol_state', p_loop_count := 7,
                                 p_source_table := 'public.protocol_state_old', p_order := 'DESC');

CALL partman.partition_data_proc(p_parent_table := 'public.contract_storage', p_loop_count := 7,
                                 p_source_table := 'public.contract_storage_old', p_order := 'DESC');

CALL partman.partition_data_proc(p_parent_table := 'public.component_balance', p_loop_count := 7,
                                 p_source_table := 'public.component_balance_old', p_order := 'DESC');