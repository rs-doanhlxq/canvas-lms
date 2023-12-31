# frozen_string_literal: true

#
# Copyright (C) 2012 - present Instructure, Inc.
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

class AppointmentGroupSubContext < ActiveRecord::Base
  belongs_to :appointment_group
  belongs_to :sub_context, polymorphic: [:group_category, :course_section]

  validates_each :sub_context do |record, attr, value|
    if record.participant_type == "User"
      record.errors.add(attr, t("errors.invalid_course_section", "Invalid course section")) unless value.blank? || (value.is_a?(CourseSection) && record.appointment_group.contexts.any?(value.course))
    else
      record.errors.add(attr, t("errors.missing_group_category", "Group appointments must have a group category")) unless value.present? && value.is_a?(GroupCategory)
      record.errors.add(attr, t("errors.invalid_group_category", "Invalid group category")) unless value && record.appointment_group.contexts.any?(value.context)
    end
  end

  def participant_type
    (sub_context_type == "GroupCategory") ? "Group" : "User"
  end
end
