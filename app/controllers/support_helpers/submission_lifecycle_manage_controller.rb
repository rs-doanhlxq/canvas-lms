# frozen_string_literal: true

#
# Copyright (C) 2018 - present Instructure, Inc.
#
# This file is part of Canvas.
#
# Canvas is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# Canvas is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.

module SupportHelpers
  class SubmissionLifecycleManageController < ApplicationController
    include SupportHelpers::ControllerHelpers

    before_action :require_site_admin

    protect_from_forgery with: :exception

    def course
      if params[:course_id]
        run_fixer(SupportHelpers::SubmissionLifecycleManage::CourseFixer, params[:course_id].to_i, @current_user.id)
      else
        render plain: "Missing course id parameter", status: :bad_request
      end
    end
  end
end
