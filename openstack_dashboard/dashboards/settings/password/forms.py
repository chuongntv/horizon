# Copyright 2013 Centrin Data Systems Ltd.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import base64
from random import randint

from django import http
from django.conf import settings
from django.forms import ValidationError  # noqa
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.debug import sensitive_variables  # noqa

from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.utils import functions as utils
from horizon.utils import validators
from openstack_dashboard import api


class PasswordForm(forms.SelfHandlingForm):
    current_password = forms.CharField(
        label=_("Current password"),
        widget=forms.PasswordInput(render_value=False),
        required=False)
    new_password = forms.RegexField(
        label=_("New password"),
        widget=forms.PasswordInput(render_value=False),
        required=False,
        regex=validators.password_validator(),
        error_messages={'invalid':
                            validators.password_validator_msg()})
    confirm_password = forms.CharField(
        label=_("Confirm new password"),
        required=False,
        widget=forms.PasswordInput(render_value=False))
    new_secret_key = forms.BooleanField(required=False)
    no_autocomplete = True

    def clean(self):
        '''Check to make sure password fields match.'''
        data = super(PasswordForm, self).clean()
        if 'new_password' in data:
            if data['new_password'] != data.get('confirm_password', None):
                raise ValidationError(_('Passwords do not match.'))
        return data

    # We have to protect the entire "data" dict because it contains the
    # oldpassword and newpassword strings.
    @sensitive_variables('data')
    def handle(self, request, data):
        user_is_editable = api.keystone.keystone_can_edit_user()

        if user_is_editable:
            try:
                if data['new_secret_key'] is True:
                    secret_key = base64.b32encode(str(randint(100000000000000, 999999999999999)))
                    api.keystone.create_credentials(request,
                                                    api.keystone.auth_utils.get_user(
                                                        request).id,
                                                    'totp',
                                                    'GEZDGNBVGY3TQOJQGEZDGNBVGY',
                                                    None)
                    response = http.HttpResponseRedirect(settings.LOGOUT_URL)
                    msg = _(str("New secret key is: ")
                            .join(str("GEZDGNBVGY3TQOJQGEZDGNBVGY"))
                            .join(str("Please log in again to continue.")))
                    utils.add_logout_reason(request, response, msg)
                    return response
                else:
                    api.keystone.user_update_own_password(request,
                                                          data['current_password'],
                                                          data['new_password'])
                    response = http.HttpResponseRedirect(settings.LOGOUT_URL)
                    msg = _("Password changed. Please log in again to continue.")
                    utils.add_logout_reason(request, response, msg)
                    return response
            except Exception:
                exceptions.handle(request,
                                  _('Unable to change password.'))
                return False
        else:
            messages.error(request, _('Changing password is not supported.'))
            return False
