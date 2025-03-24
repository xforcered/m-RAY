from .tso.racf_options import *

def racf_checks(mainframe, client):
    sections = racf_options(mainframe, client)
    racf_for_unix_active(sections)
    jesspool_res_active(sections)
    dfsms_racf_active(sections)
    mcs_console_res_active(sections)
    opercmds_res_active(sections)
    facility_res_active(sections)
    when_program_active(sections)
    group_access_chk_active(sections)
    real_data_set_names(sections)
    retention_period(sections)
    saudit_value_set(sections)
    jes_batchallracf(sections)
    jes_xbmallracf(sections)
    inactive_id_revoke(sections)
    password_history(sections)