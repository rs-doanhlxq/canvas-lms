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

import React, {useEffect, useRef, useState} from 'react'
import {useScope as useI18nScope} from '@canvas/i18n'

import {View} from '@instructure/ui-view'
import {Flex} from '@instructure/ui-flex'
import {Transition} from '@instructure/ui-motion'
import {Spinner} from '@instructure/ui-spinner'
import {Button} from '@instructure/ui-buttons'
import {IconSearchLine} from '@instructure/ui-icons'

import {showFlashError, showFlashSuccess} from '@canvas/alerts/react/FlashAlert'
import {GradingSchemeView} from './view/GradingSchemeView'
import {GradingSchemeTemplateView} from './view/GradingSchemeTemplateView'
import {useGradingSchemes} from '../hooks/useGradingSchemes'
import {useDefaultGradingScheme} from '../hooks/useDefaultGradingScheme'
import {useGradingSchemeCreate} from '../hooks/useGradingSchemeCreate'
import {useGradingSchemeDelete} from '../hooks/useGradingSchemeDelete'
import {useGradingSchemeUpdate} from '../hooks/useGradingSchemeUpdate'
import {
  GradingScheme,
  GradingSchemeCardData,
  GradingSchemeTemplate,
} from '../../gradingSchemeApiModel'

import {
  GradingSchemeEditableData,
  GradingSchemeInput,
  GradingSchemeInputHandle,
} from './form/GradingSchemeInput'
import {defaultPointsGradingScheme} from '../../defaultPointsGradingScheme'
import {canManageAccountGradingSchemes} from '../helpers/gradingSchemePermissions'
import {GradingSchemeTable} from './GradingSchemeTable'
import GradingSchemeViewModal from './GradingSchemeViewModal'
import GradingSchemeEditModal from './GradingSchemeEditModal'
import {TextInput} from '@instructure/ui-text-input'
import GradingSchemeCreateModal from './GradingSchemeCreateModal'
import {Heading} from '@instructure/ui-heading'

const I18n = useI18nScope('GradingSchemeManagement')

interface GradingSchemeTemplateCardData {
  creating: boolean
  gradingSchemeTemplate: GradingSchemeTemplate
}

export interface GradingSchemesManagementProps {
  contextId: string
  contextType: 'Account' | 'Course'
  onGradingSchemesChanged?: () => any
  pointsBasedGradingSchemesEnabled: boolean
  archivedGradingSchemesEnabled: boolean
}

export const GradingSchemesManagement = ({
  contextType,
  contextId,
  onGradingSchemesChanged,
  pointsBasedGradingSchemesEnabled,
  archivedGradingSchemesEnabled,
}: GradingSchemesManagementProps) => {
  const {createGradingScheme /* createGradingSchemeStatus */} = useGradingSchemeCreate()
  const {deleteGradingScheme /* deleteGradingSchemeStatus */} = useGradingSchemeDelete()
  const {updateGradingScheme /* deleteGradingSchemeStatus */} = useGradingSchemeUpdate()

  const [gradingSchemeCards, setGradingSchemeCards] = useState<GradingSchemeCardData[] | undefined>(
    undefined
  )

  const [gradingSchemeCreating, setGradingSchemeCreating] = useState<
    GradingSchemeTemplateCardData | undefined
  >(undefined)

  const [editing, setEditing] = useState<boolean>(false)
  const [selectedGradingScheme, setSelectedGradingScheme] = useState<GradingScheme | undefined>(
    undefined
  )
  const {loadGradingSchemes} = useGradingSchemes()
  const {loadDefaultGradingScheme} = useDefaultGradingScheme()
  const [defaultGradingScheme, setDefaultGradingScheme] = useState<GradingScheme | undefined>(
    undefined
  )

  const gradingSchemeCreateRef = useRef<GradingSchemeInputHandle>(null)
  const gradingSchemeUpdateRef = useRef<GradingSchemeInputHandle>(null)
  useEffect(() => {
    loadGradingSchemes(contextType, contextId)
      .then(gradingSchemes => {
        setGradingSchemeCards(
          gradingSchemes.map(scheme => {
            return {
              gradingScheme: scheme,
              editing: false,
              creating: false,
            } as GradingSchemeCardData
          })
        )
      })
      .catch(error => {
        showFlashError(I18n.t('There was an error while loading grading schemes'))(error)
      })
    loadDefaultGradingScheme(contextType, contextId)
      .then(loadedDefaultGradingScheme => {
        setDefaultGradingScheme(loadedDefaultGradingScheme)
      })
      .catch(error => {
        showFlashError(I18n.t('There was an error while loading the default grading scheme'))(error)
      })
  }, [loadGradingSchemes, loadDefaultGradingScheme, contextType, contextId])

  const handleGradingSchemeDelete = async (gradingSchemeId: string) => {
    if (!gradingSchemeCards) return

    // TODO: is there a good inst ui component for confirmation dialog?
    // TODO: replace with modal dialog for delete
    if (
      // eslint-disable-next-line no-alert
      !window.confirm(
        I18n.t('confirm.delete', 'Are you sure you want to delete this grading scheme?')
      )
    ) {
      return
    }

    const gradingSchemeToDelete = gradingSchemeCards.filter(
      gradingSchemeCard => gradingSchemeId === gradingSchemeCard.gradingScheme.id
    )[0].gradingScheme

    try {
      await deleteGradingScheme(
        gradingSchemeToDelete.context_type,
        gradingSchemeToDelete.context_id,
        gradingSchemeId
      )
      showFlashSuccess(I18n.t('Grading scheme was successfully removed.'))()
      if (onGradingSchemesChanged) {
        // if parent supplied a callback method, inform parent that grading standards changed (one was removed)
        onGradingSchemesChanged()
      }
      setGradingSchemeCards(
        gradingSchemeCards.filter(
          gradingSchemeCard => gradingSchemeId !== gradingSchemeCard.gradingScheme.id
        )
      )
      setSelectedGradingScheme(undefined)
      setEditing(false)
    } catch (error) {
      showFlashError(I18n.t('There was an error while removing the grading scheme'))(error as Error)
    }
  }

  const handleCreateScheme = async (gradingSchemeFormInput: GradingSchemeEditableData) => {
    if (!gradingSchemeCards) {
      return
    }
    // TODO: if (!saving) {
    try {
      const gradingScheme = await createGradingScheme(contextType, contextId, {
        ...gradingSchemeFormInput,
        points_based: gradingSchemeFormInput.pointsBased,
        scaling_factor: gradingSchemeFormInput.scalingFactor,
      })
      setGradingSchemeCreating(undefined)
      const updatedGradingSchemeCards = [{gradingScheme, editing: false}, ...gradingSchemeCards]
      setGradingSchemeCards(updatedGradingSchemeCards)
      showFlashSuccess(I18n.t('Grading scheme was successfully saved.'))()
      if (onGradingSchemesChanged) {
        // if parent supplied a callback method, inform parent that grading standards changed (one was added)
        onGradingSchemesChanged()
      }
    } catch (error) {
      showFlashError(I18n.t('There was an error while creating the grading scheme'))(error as Error)
    }
  }

  const handleUpdateScheme = async (
    gradingSchemeFormInput: GradingSchemeEditableData,
    gradingSchemeId: string
  ) => {
    if (!gradingSchemeCards) {
      return
    }
    // TODO: if (!saving) {

    try {
      const updatedGradingScheme = await updateGradingScheme(contextType, contextId, {
        title: gradingSchemeFormInput.title,
        data: gradingSchemeFormInput.data,
        points_based: gradingSchemeFormInput.pointsBased,
        scaling_factor: gradingSchemeFormInput.scalingFactor,
        id: gradingSchemeId,
      })

      const updatedGradingSchemeCards = gradingSchemeCards.map(gradingSchemeCard => {
        if (gradingSchemeCard.gradingScheme.id === gradingSchemeId) {
          gradingSchemeCard.gradingScheme = updatedGradingScheme
          gradingSchemeCard.editing = false
        }
        return gradingSchemeCard
      })
      setGradingSchemeCards(updatedGradingSchemeCards)
      setSelectedGradingScheme(undefined)
      setEditing(false)
      showFlashSuccess(I18n.t('Grading scheme was successfully saved.'))()
      if (onGradingSchemesChanged) {
        // if parent supplied a callback method, inform parent that grading standards changed (one was updated)
        onGradingSchemesChanged()
      }
    } catch (error) {
      showFlashError(I18n.t('There was an error while saving the grading scheme'))(error as Error)
    }
  }

  const addNewGradingScheme = () => {
    if (!gradingSchemeCards || !defaultGradingScheme) return
    const newStandard: GradingSchemeTemplateCardData = {
      creating: true,
      gradingSchemeTemplate: defaultGradingScheme,
    }
    setGradingSchemeCreating(newStandard)
  }

  function editGradingScheme(gradingSchemeId: string) {
    if (!gradingSchemeCards) {
      throw new Error('grading scheme cards cannot be edited until after they are loaded')
    }
    if (editing) return
    setSelectedGradingScheme(undefined)
    setGradingSchemeCards(
      gradingSchemeCards.map(gradingSchemeCard => {
        if (gradingSchemeCard.gradingScheme.id === gradingSchemeId) {
          setSelectedGradingScheme(gradingSchemeCard.gradingScheme)
          setEditing(true)
          gradingSchemeCard.editing = true
        }
        return gradingSchemeCard
      })
    )
  }

  function openGradingScheme(gradingScheme: GradingScheme) {
    setSelectedGradingScheme(gradingScheme)
    setEditing(false)
  }

  function handleCancelEdit(gradingSchemeId: string) {
    if (!gradingSchemeCards) {
      throw new Error('grading scheme cards cannot be edited until after they are loaded')
    }
    setEditing(false)
    setSelectedGradingScheme(undefined)
    setGradingSchemeCards(
      gradingSchemeCards.map(gradingSchemeCard => {
        if (gradingSchemeCard.gradingScheme.id === gradingSchemeId) {
          gradingSchemeCard.editing = false
        }
        return gradingSchemeCard
      })
    )
  }

  function handleCancelCreate() {
    setGradingSchemeCreating(undefined)
  }

  function canManageScheme(gradingScheme: GradingScheme) {
    if (editing) {
      return false
    }
    if (gradingSchemeCreating) {
      return false
    }
    if (!gradingScheme.permissions.manage) {
      return false
    }
    if (!canManageAccountGradingSchemes(contextType, gradingScheme.context_type)) {
      return false
    }
    return !gradingScheme.assessed_assignment
  }

  return (
    <>
      <View>
        <Flex justifyItems="end">
          {archivedGradingSchemesEnabled && (
            <Flex.Item margin="medium small 0 0" shouldShrink={true}>
              <TextInput
                type="search"
                placeholder={I18n.t('Search...')}
                renderBeforeInput={() => <IconSearchLine inline={false} />}
                width="22.5rem"
              />
            </Flex.Item>
          )}
          <Flex.Item margin="medium 0 0 small">
            <Button
              color="primary"
              onClick={addNewGradingScheme}
              disabled={!!(gradingSchemeCreating || editing)}
            >
              {I18n.t('New Grading Scheme')}
            </Button>
          </Flex.Item>
        </Flex>
      </View>
      {!gradingSchemeCards || !defaultGradingScheme ? (
        <Spinner renderTitle="Loading" size="small" margin="0 0 0 medium" />
      ) : (
        <>
          {!archivedGradingSchemesEnabled && gradingSchemeCreating ? (
            <>
              <Transition transitionOnMount={true} unmountOnExit={true} in={true} type="fade">
                <View
                  as="div"
                  display="block"
                  padding="small"
                  margin="medium none medium none"
                  borderWidth="small"
                  borderRadius="medium"
                  withVisualDebug={false}
                  key="grading-scheme-create"
                >
                  <GradingSchemeInput
                    ref={gradingSchemeCreateRef}
                    schemeInputType="percentage"
                    initialFormDataByInputType={{
                      percentage: {
                        data: defaultGradingScheme.data,
                        title: '',
                        scalingFactor: 1.0,
                        pointsBased: false,
                      },
                      points: {
                        data: defaultPointsGradingScheme.data,
                        title: '',
                        scalingFactor: defaultPointsGradingScheme.scaling_factor,
                        pointsBased: true,
                      },
                    }}
                    pointsBasedGradingSchemesFeatureEnabled={pointsBasedGradingSchemesEnabled}
                    onSave={handleCreateScheme}
                    archivedGradingSchemesEnabled={archivedGradingSchemesEnabled}
                  />
                  <hr />
                  <Flex justifyItems="end">
                    <Flex.Item>
                      <Button onClick={handleCancelCreate} margin="0 x-small 0 0">
                        {I18n.t('Cancel')}
                      </Button>
                      <Button
                        onClick={() => gradingSchemeCreateRef.current?.savePressed()}
                        color="primary"
                      >
                        {I18n.t('Save')}
                      </Button>
                    </Flex.Item>
                  </Flex>
                </View>
              </Transition>
            </>
          ) : (
            <></>
          )}
          {archivedGradingSchemesEnabled && defaultGradingScheme ? (
            <>
              <Heading
                level="h2"
                margin="medium 0"
                themeOverride={{h2FontWeight: 700, lineHeight: 1.05}}
              >
                {I18n.t('Canvas Default')}
              </Heading>
              <GradingSchemeTable
                gradingSchemeCards={[{editing: false, gradingScheme: defaultGradingScheme}]}
                caption="Canvas Default Grading Schemes"
                editGradingScheme={editGradingScheme}
                openGradingScheme={openGradingScheme}
                handleGradingSchemeDelete={handleGradingSchemeDelete}
                defaultScheme={true}
              />
              <Heading
                level="h2"
                margin="large 0 medium"
                themeOverride={{h2FontWeight: 700, lineHeight: 1.05}}
              >
                {I18n.t('Your Grading Schemes')}
              </Heading>
              <GradingSchemeTable
                gradingSchemeCards={gradingSchemeCards}
                caption="Grading Schemes"
                editGradingScheme={editGradingScheme}
                openGradingScheme={openGradingScheme}
                handleGradingSchemeDelete={handleGradingSchemeDelete}
              />
              <GradingSchemeViewModal
                open={selectedGradingScheme !== undefined && !editing}
                gradingScheme={selectedGradingScheme}
                handleClose={() => setSelectedGradingScheme(undefined)}
                handleGradingSchemeDelete={handleGradingSchemeDelete}
                editGradingScheme={editGradingScheme}
                pointsBasedGradingSchemesEnabled={pointsBasedGradingSchemesEnabled}
                canManageScheme={canManageScheme}
              />
              <GradingSchemeEditModal
                open={selectedGradingScheme !== undefined && editing}
                gradingScheme={selectedGradingScheme}
                handleCancelEdit={handleCancelEdit}
                handleUpdateScheme={handleUpdateScheme}
                defaultGradingSchemeTemplate={defaultGradingScheme}
                defaultPointsGradingScheme={defaultPointsGradingScheme}
                pointsBasedGradingSchemesEnabled={pointsBasedGradingSchemesEnabled}
                archivedGradingSchemesEnabled={archivedGradingSchemesEnabled}
                handleGradingSchemeDelete={handleGradingSchemeDelete}
              />
              <GradingSchemeCreateModal
                open={!!gradingSchemeCreating}
                handleCreateScheme={handleCreateScheme}
                pointsBasedGradingSchemesEnabled={pointsBasedGradingSchemesEnabled}
                archivedGradingSchemesEnabled={archivedGradingSchemesEnabled}
                defaultGradingSchemeTemplate={defaultGradingScheme}
                defaultPointsGradingScheme={defaultPointsGradingScheme}
                handleCancelCreate={handleCancelCreate}
              />
            </>
          ) : (
            gradingSchemeCards.map(gradingSchemeCard => (
              <View
                display="block"
                padding="small"
                margin="medium none medium none"
                borderWidth="small"
                borderRadius="medium"
                key={gradingSchemeCard.gradingScheme.id}
              >
                {gradingSchemeCard.editing ? (
                  <Transition transitionOnMount={true} unmountOnExit={true} in={true} type="fade">
                    <>
                      <GradingSchemeInput
                        schemeInputType={
                          gradingSchemeCard.gradingScheme.points_based ? 'points' : 'percentage'
                        }
                        initialFormDataByInputType={{
                          percentage: {
                            data: gradingSchemeCard.gradingScheme.points_based
                              ? defaultGradingScheme.data
                              : gradingSchemeCard.gradingScheme.data,
                            title: gradingSchemeCard.gradingScheme.title,
                            pointsBased: false,
                            scalingFactor: 1.0,
                          },
                          points: {
                            data: gradingSchemeCard.gradingScheme.points_based
                              ? gradingSchemeCard.gradingScheme.data
                              : defaultPointsGradingScheme.data,
                            title: gradingSchemeCard.gradingScheme.title,
                            pointsBased: true,
                            scalingFactor: gradingSchemeCard.gradingScheme.points_based
                              ? gradingSchemeCard.gradingScheme.scaling_factor
                              : defaultPointsGradingScheme.scaling_factor,
                          },
                        }}
                        ref={gradingSchemeUpdateRef}
                        pointsBasedGradingSchemesFeatureEnabled={pointsBasedGradingSchemesEnabled}
                        archivedGradingSchemesEnabled={archivedGradingSchemesEnabled}
                        onSave={modifiedGradingScheme =>
                          handleUpdateScheme(
                            modifiedGradingScheme,
                            gradingSchemeCard.gradingScheme.id
                          )
                        }
                      />
                      <hr />
                      <Flex justifyItems="end">
                        <Flex.Item>
                          <Button
                            onClick={() => handleCancelEdit(gradingSchemeCard.gradingScheme.id)}
                            margin="0 x-small 0 0"
                          >
                            {I18n.t('Cancel')}
                          </Button>
                          <Button
                            onClick={() => gradingSchemeUpdateRef.current?.savePressed()}
                            color="primary"
                          >
                            {I18n.t('Save')}
                          </Button>
                        </Flex.Item>
                      </Flex>
                    </>
                  </Transition>
                ) : (
                  <Transition transitionOnMount={true} unmountOnExit={true} in={true} type="fade">
                    <View display="block">
                      <GradingSchemeView
                        gradingScheme={gradingSchemeCard.gradingScheme}
                        pointsBasedGradingSchemesEnabled={pointsBasedGradingSchemesEnabled}
                        archivedGradingSchemesEnabled={archivedGradingSchemesEnabled}
                        disableDelete={!canManageScheme(gradingSchemeCard.gradingScheme)}
                        disableEdit={!canManageScheme(gradingSchemeCard.gradingScheme)}
                        onDeleteRequested={() =>
                          handleGradingSchemeDelete(gradingSchemeCard.gradingScheme.id)
                        }
                        onEditRequested={() =>
                          editGradingScheme(gradingSchemeCard.gradingScheme.id)
                        }
                      />
                    </View>
                  </Transition>
                )}
              </View>
            ))
          )}
          {!archivedGradingSchemesEnabled && (
            <View
              display="block"
              padding="small"
              margin="medium none"
              borderWidth="small"
              borderRadius="small"
            >
              <View display="block">
                <GradingSchemeTemplateView
                  allowDuplicate={false}
                  onDuplicationRequested={addNewGradingScheme}
                  gradingSchemeTemplate={defaultGradingScheme}
                />
              </View>
            </View>
          )}
        </>
      )}
    </>
  )
}
