# frozen_string_literal: true

#
# Copyright (C) 2011 - present Instructure, Inc.
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
#

describe UserListsController do
  it "does not fail for permission to add students (non-granular)" do
    course_factory
    @course.root_account.disable_feature!(:granular_permissions_manage_users)
    role = custom_account_role("myadmin", account: @course.account)
    account_admin_user_with_role_changes(role:, role_changes: { manage_students: true })
    user_session(@user)

    post "create", params: { course_id: @course.id, user_list: "" }, format: "json"
    expect(response).to be_successful
  end

  it "does not fail for permission to add students (granular)" do
    course_factory
    @course.root_account.enable_feature!(:granular_permissions_manage_users)
    role = custom_account_role("myadmin", account: @course.account)
    account_admin_user_with_role_changes(role:, role_changes: { add_student_to_course: true })
    user_session(@user)

    post "create", params: { course_id: @course.id, user_list: "" }, format: "json"
    expect(response).to be_successful
  end

  it "uses version 2 if requested" do
    course_with_teacher(active_all: true)
    user_session(@user)

    expect(UserListV2).to receive(:new).once.with("list", search_type: "unique_id", root_account: Account.default, current_user: @user, can_read_sis: true)
    post "create", params: { course_id: @course.id, user_list: "list", v2: true, search_type: "unique_id" }, format: "json"
    expect(response).to be_successful
  end
end
