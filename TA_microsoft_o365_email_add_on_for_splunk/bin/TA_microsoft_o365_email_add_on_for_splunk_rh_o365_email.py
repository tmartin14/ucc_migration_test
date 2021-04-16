
import ta_microsoft_o365_email_add_on_for_splunk_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'interval',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""", 
        )
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            min_len=1, 
            max_len=80, 
        )
    ), 
    field.RestField(
        'audit_email_account',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'tenant',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'endpoint',
        required=True,
        encrypted=False,
        default='worldwide',
        validator=None
    ), 
    field.RestField(
        'get_attachment_info',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'file_hash_algorithm',
        required=False,
        encrypted=False,
        default='md5',
        validator=None
    ), 
    field.RestField(
        'macro_analysis',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'read_zip_files',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'extract_body_iocs',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_body',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_body_preview',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_message_path',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_auth_results',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_spf_results',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_dkim_signature',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_x_headers',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_internet_headers',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'get_tracking_pixel',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'global_account',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'o365_email',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
