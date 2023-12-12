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

import {render} from '@testing-library/react'
import React from 'react'

import {PeerReviewOptions} from '../PeerReviewOptions'

const defaultProps = {
  peerReviewAssignment: 'off',
  setPeerReviewAssignment: () => {},
  peerReviewsPerStudent: 1,
  setPeerReviewsPerStudent: () => {},
  peerReviewDueDate: '',
  setPeerReviewDueDate: () => {},
}

const renderPeerReviewOptions = (props = {}) => {
  return render(<PeerReviewOptions {...props} />)
}
describe('PeerReviewOptions', () => {
  it('renders', () => {
    const {getByText, queryByText} = renderPeerReviewOptions(defaultProps)
    expect(getByText('Peer Reviews')).toBeInTheDocument()
    expect(getByText('Off')).toBeInTheDocument()
    expect(getByText('Assign manually')).toBeInTheDocument()
    expect(getByText('Automatically assign')).toBeInTheDocument()
    expect(queryByText('Reviews Per Student')).not.toBeInTheDocument()
    expect(queryByText('Reviews Due')).not.toBeInTheDocument()
    expect(queryByText('If left blank, uses due date')).not.toBeInTheDocument()
  })

  it('shows more options when peer review is active', () => {
    const {getByText, getByTestId} = renderPeerReviewOptions({
      ...defaultProps,
      peerReviewAssignment: 'manually',
    })
    expect(getByText('Peer Reviews')).toBeInTheDocument()
    expect(getByText('Off')).toBeInTheDocument()
    expect(getByText('Assign manually')).toBeInTheDocument()
    expect(getByText('Automatically assign')).toBeInTheDocument()
    expect(getByText('Reviews Per Student')).toBeInTheDocument()
    expect(getByTestId('peer-review-due-date-container')).toBeInTheDocument()
    expect(getByText('If left blank, uses due date')).toBeInTheDocument()
  })
})
