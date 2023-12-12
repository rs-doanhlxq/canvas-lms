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

import React, {useCallback} from 'react'
import {useActionData, useLoaderData, useNavigate} from 'react-router-dom'
import {Breadcrumb} from '@instructure/ui-breadcrumb'
import {Button} from '@instructure/ui-buttons'
import {Flex} from '@instructure/ui-flex'
import {Heading} from '@instructure/ui-heading'
import {
  IconDownloadLine,
  IconEditLine,
  IconPrinterLine,
  IconReviewScreenLine,
  IconShareLine,
} from '@instructure/ui-icons'
import {View} from '@instructure/ui-view'
import type {PortfolioDetailData} from '../types'
import PortfolioView from './PortfolioView'

const PortfolioViewPage = () => {
  const navigate = useNavigate()
  const create_portfolio = useActionData() as PortfolioDetailData
  const edit_portfolio = useLoaderData() as PortfolioDetailData
  const portfolio = create_portfolio || edit_portfolio

  const handleEditClick = useCallback(() => {
    navigate(`../edit/${portfolio.id}`)
  }, [navigate, portfolio.id])

  return (
    <View as="div" id="foo" maxWidth="986px" margin="0 auto">
      <Breadcrumb label="You are here:" size="small">
        <Breadcrumb.Link href={`/users/${ENV.current_user.id}/passport/portfolios/dashboard`}>
          Portfolios
        </Breadcrumb.Link>
        <Breadcrumb.Link>{portfolio.title}</Breadcrumb.Link>
      </Breadcrumb>
      <Flex as="div" margin="0 0 medium 0">
        <Flex.Item shouldGrow={true}>
          <Heading level="h1" themeOverride={{h1FontWeight: 700}}>
            {portfolio.title}
          </Heading>
        </Flex.Item>
        <Flex.Item>
          <Button margin="0 x-small 0 0" renderIcon={IconEditLine} onClick={handleEditClick}>
            Edit
          </Button>
          <Button margin="0 x-small 0 0" renderIcon={IconDownloadLine}>
            Download
          </Button>
          <Button margin="0 x-small 0 0" renderIcon={IconPrinterLine}>
            Print
          </Button>
          <Button margin="0 x-small 0 0" renderIcon={IconReviewScreenLine}>
            Preview
          </Button>
          <Button color="primary" margin="0" renderIcon={IconShareLine}>
            Share
          </Button>
        </Flex.Item>
      </Flex>
      <PortfolioView portfolio={portfolio} />
    </View>
  )
}

export default PortfolioViewPage
