/*
 * Copyright (C) 2023 - present Instructure, Inc.
 *
 * This file is part of Canvas.
 *
 * Canvas is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3 of the License.
 *
 * Canvas is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react'

import {View} from '@instructure/ui-view'

import {AssignmentGroupSelect} from './AssignmentGroupSelect'
import {DisplayGradeAs} from './DisplayGradeAs'
import {PointsPossible} from './PointsPossible'
import {PeerReviewOptions} from './PeerReviewOptions'
import {AssignmentDueDatesManager} from './AssignmentDueDatesManager'
import {SyncToSisCheckbox} from './SyncToSisCheckbox'

type Props = {
  assignmentGroups: [{_id: string; name: string}]
  pointsPossible: number
  setPointsPossible: (points: number) => void
  displayGradeAs: string
  setDisplayGradeAs: (id: string | undefined) => void
  assignmentGroup: string
  setAssignmentGroup: (id: string | undefined) => void
  peerReviewAssignment: string
  setPeerReviewAssignment: (id: string | undefined) => void
  peerReviewsPerStudent: number
  setPeerReviewsPerStudent: (peerReviewsPerStudent: number) => void
  peerReviewDueDate: string
  setPeerReviewDueDate: (peerReviewDueDate: string) => void
  postToSis: boolean
  setPostToSis: (postToSis: boolean) => void
}

export const GradedDiscussionOptions = ({
  assignmentGroups,
  pointsPossible,
  setPointsPossible,
  displayGradeAs,
  setDisplayGradeAs,
  assignmentGroup,
  setAssignmentGroup,
  peerReviewAssignment,
  setPeerReviewAssignment,
  peerReviewsPerStudent,
  setPeerReviewsPerStudent,
  peerReviewDueDate,
  setPeerReviewDueDate,
  postToSis,
  setPostToSis,
}: Props) => {
  return (
    <View as="div">
      <View as="div" margin="medium 0">
        <PointsPossible pointsPossible={pointsPossible} setPointsPossible={setPointsPossible} />
      </View>
      <View as="div" margin="medium 0">
        <DisplayGradeAs displayGradeAs={displayGradeAs} setDisplayGradeAs={setDisplayGradeAs} />
      </View>
      {ENV.POST_TO_SIS && (
        <View as="div" margin="medium 0">
          <SyncToSisCheckbox postToSis={postToSis} setPostToSis={setPostToSis} />
        </View>
      )}
      <View as="div" margin="medium 0">
        <AssignmentGroupSelect
          assignmentGroup={assignmentGroup}
          setAssignmentGroup={setAssignmentGroup}
          availableAssignmentGroups={assignmentGroups}
        />
      </View>
      <View as="div" margin="small 0">
        <PeerReviewOptions
          peerReviewAssignment={peerReviewAssignment}
          setPeerReviewAssignment={setPeerReviewAssignment}
          peerReviewsPerStudent={peerReviewsPerStudent}
          setPeerReviewsPerStudent={setPeerReviewsPerStudent}
          peerReviewDueDate={peerReviewDueDate}
          setPeerReviewDueDate={setPeerReviewDueDate}
        />
      </View>
      <View as="div" margin="medium 0">
        <AssignmentDueDatesManager />
      </View>
    </View>
  )
}
