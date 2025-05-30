// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/timeutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault/activity"
	"google.golang.org/protobuf/proto"
)

// computeCurrentMonthForBillingPeriod computes the current month's data with respect
// to a billing period.
func (a *ActivityLog) computeCurrentMonthForBillingPeriod(byMonth map[int64]*processMonth, startTime time.Time, endTime time.Time) (*activity.MonthRecord, error) {
	return a.computeCurrentMonthForBillingPeriodInternal(byMonth, startTime, endTime)
}

func (a *ActivityLog) computeCurrentMonthForBillingPeriodInternal(byMonth map[int64]*processMonth, startTime time.Time, endTime time.Time) (*activity.MonthRecord, error) {
	if timeutil.IsCurrentMonth(startTime, a.clock.Now().UTC()) {
		monthlyComputation := a.transformMonthBreakdowns(byMonth)
		if len(monthlyComputation) > 1 {
			a.logger.Warn("monthly in-memory activitylog computation returned multiple months of data", "months returned", len(byMonth))
		}
		if len(monthlyComputation) > 0 {
			return monthlyComputation[0], nil
		}
	}

	// There's at most one month of data here. We should validate this assumption explicitly
	if len(byMonth) > 1 {
		return nil, errors.New(fmt.Sprintf("multiple months of data found in partial month's client count breakdowns: %+v\n", byMonth))
	}

	// counts including new clients and old clients
	totalCounts := &activity.CountsRecord{}
	// new client counts
	newCounts := &activity.CountsRecord{}
	// namespaces of new clients
	newNamespaces := make([]*activity.MonthlyNamespaceRecord, 0)
	// namespaces including both namespaces with new and repeated clients
	totalNamespaces := make([]*activity.MonthlyNamespaceRecord, 0)

	monthRecord := &activity.MonthRecord{
		Timestamp:  timeutil.StartOfMonth(endTime).UTC().Unix(),
		Counts:     totalCounts,
		Namespaces: totalNamespaces,
		NewClients: &activity.NewClientRecord{
			Counts:     newCounts,
			Namespaces: newNamespaces,
		},
	}
	if len(byMonth) == 0 {
		return monthRecord, nil
	}

	// we've already checked that byMonth has length of 1, so this will get the
	// value of the only entry in the map
	var month *processMonth
	for _, month = range byMonth {
	}

	// This month should have clients
	if month.NewClients == nil || month.NewClients.Counts == nil || month.Counts == nil {
		return nil, errors.New("malformed current month used to calculate current month's activity")
	}

	// clients in current billing period until last month
	currentBillingPeriodClients := a.GetClientIDsUsageInfo()
	for nsID, namespace := range month.Namespaces {
		namespaceActivity := &activity.MonthlyNamespaceRecord{NamespaceID: nsID, Counts: &activity.CountsRecord{}}
		newNamespaceActivity := &activity.MonthlyNamespaceRecord{NamespaceID: nsID, Counts: &activity.CountsRecord{}}
		mountsActivity := make([]*activity.MountRecord, 0)
		newMountsActivity := make([]*activity.MountRecord, 0)

		for mountAccessor, mount := range namespace.Mounts {
			mountPath := a.mountAccessorToMountPath(mountAccessor)

			mountCounts := &activity.CountsRecord{}
			newMountCounts := &activity.CountsRecord{}

			for _, typ := range ActivityClientTypes {
				for clientID := range mount.Counts.clientsByType(typ) {
					if _, ok := currentBillingPeriodClients[clientID]; !ok {
						// new client
						a.incrementCount(newCounts, 1, typ)
						a.incrementCount(newMountCounts, 1, typ)
						a.incrementCount(newNamespaceActivity.Counts, 1, typ)
					}

					// increment the per mount, per namespace, and total counts
					// for each client
					a.incrementCount(totalCounts, 1, typ)
					a.incrementCount(mountCounts, 1, typ)
					a.incrementCount(namespaceActivity.Counts, 1, typ)
				}
			}

			// if there are any new clients on this mount, add it to the
			// list of new mounts
			if newMountCounts.HasCounts() {
				newMountsActivity = append(newMountsActivity, &activity.MountRecord{MountPath: mountPath, Counts: newMountCounts})
			}
			mountsActivity = append(mountsActivity, &activity.MountRecord{MountPath: mountPath, Counts: mountCounts})
		}

		namespaceActivity.Mounts = mountsActivity
		totalNamespaces = append(totalNamespaces, namespaceActivity)

		// if there are any new clients on this namespace, add it to the
		// list of new namespaces
		if newNamespaceActivity.Counts.HasCounts() {
			newNamespaceActivity.Mounts = newMountsActivity
			newNamespaces = append(newNamespaces, newNamespaceActivity)
		}
	}

	monthRecord.Namespaces = totalNamespaces
	monthRecord.NewClients.Namespaces = newNamespaces
	return monthRecord, nil
}

// incrementCount modifies the passed-in counts record by incrementing the
// client type's field by num
func (a *ActivityLog) incrementCount(c *activity.CountsRecord, num int, typ string) {
	switch typ {
	case entityActivityType:
		c.EntityClients += num
	case nonEntityTokenActivityType:
		c.NonEntityClients += num
	case secretSyncActivityType:
		c.SecretSyncs += num
	case ACMEActivityType:
		c.ACMEClients += num
	}
}

type processByNamespaceID struct {
	id string
	*processByNamespace
}

func (s summaryByNamespace) sort() []*processByNamespaceID {
	namespaces := make([]*processByNamespaceID, 0, len(s))
	for nsID, namespace := range s {
		namespaces = append(namespaces, &processByNamespaceID{id: nsID, processByNamespace: namespace})
	}
	slices.SortStableFunc(namespaces, func(a, b *processByNamespaceID) int {
		return strings.Compare(a.id, b.id)
	})
	return namespaces
}

type processMountAccessor struct {
	accessor string
	*processMount
}

func (s summaryByMount) sort() []*processMountAccessor {
	mounts := make([]*processMountAccessor, 0, len(s))
	for mountAccessor, mount := range s {
		mounts = append(mounts, &processMountAccessor{accessor: mountAccessor, processMount: mount})
	}
	slices.SortStableFunc(mounts, func(a, b *processMountAccessor) int {
		return strings.Compare(a.accessor, b.accessor)
	})
	return mounts
}

func (c clientIDSet) sort() []string {
	clientIDs := make([]string, 0, len(c))
	for clientID := range c {
		clientIDs = append(clientIDs, clientID)
	}
	sort.Strings(clientIDs)
	return clientIDs
}

// sortALResponseNamespaces sorts the namespaces for activity log responses.
func (a *ActivityLog) sortALResponseNamespaces(byNamespaceResponse []*ResponseNamespace) {
	sort.Slice(byNamespaceResponse, func(i, j int) bool {
		return byNamespaceResponse[i].Counts.Clients > byNamespaceResponse[j].Counts.Clients
	})
}

// transformALNamespaceBreakdowns takes the namespace breakdowns stored in the intermediary
// struct used in precomputation segment traversal and to store the current month data and
// reorganizes it into query structs. This helper is used by the partial month endpoint so as to
// not have to maintain two separate response data computations for two separate APIs.
func (a *ActivityLog) transformALNamespaceBreakdowns(nsData map[string]*processByNamespace) []*activity.NamespaceRecord {
	byNamespace := make([]*activity.NamespaceRecord, 0)
	for nsID, ns := range nsData {

		nsRecord := activity.NamespaceRecord{
			NamespaceID:     nsID,
			Entities:        uint64(ns.Counts.countByType(entityActivityType)),
			NonEntityTokens: uint64(ns.Counts.countByType(nonEntityTokenActivityType)),
			SecretSyncs:     uint64(ns.Counts.countByType(secretSyncActivityType)),
			ACMEClients:     uint64(ns.Counts.countByType(ACMEActivityType)),
			Mounts:          a.transformActivityLogMounts(ns.Mounts),
		}
		byNamespace = append(byNamespace, &nsRecord)
	}
	return byNamespace
}

// limitNamespacesInALResponse will truncate the number of namespaces shown in the activity
// endpoints to the number specified in limitNamespaces (the API filtering parameter)
func (a *ActivityLog) limitNamespacesInALResponse(byNamespaceResponse []*ResponseNamespace, limitNamespaces int) (*ResponseCounts, []*ResponseNamespace) {
	if limitNamespaces > len(byNamespaceResponse) {
		limitNamespaces = len(byNamespaceResponse)
	}
	byNamespaceResponse = byNamespaceResponse[:limitNamespaces]
	// recalculate total entities and tokens
	totalCounts := &ResponseCounts{}
	for _, namespaceData := range byNamespaceResponse {
		totalCounts.Add(&namespaceData.Counts)
	}
	return totalCounts, byNamespaceResponse
}

// transformActivityLogMounts is a helper used to reformat data for transformMonthlyNamespaceBreakdowns.
// For more details, please see the function comment for transformMonthlyNamespaceBreakdowns
func (a *ActivityLog) transformActivityLogMounts(mts map[string]*processMount) []*activity.MountRecord {
	mounts := make([]*activity.MountRecord, 0)
	for mountAccessor, mountCounts := range mts {
		mount := activity.MountRecord{
			MountPath: a.mountAccessorToMountPath(mountAccessor),
			Counts:    mountCounts.Counts.toCountsRecord(),
		}
		mounts = append(mounts, &mount)
	}
	return mounts
}

// sortActivityLogMonthsResponse contains the sorting logic for the months
// portion of the activity log response.
func (a *ActivityLog) sortActivityLogMonthsResponse(months []*ResponseMonth) {
	// Sort the months in ascending order of timestamps
	sort.Slice(months, func(i, j int) bool {
		firstTimestamp, errOne := time.Parse(time.RFC3339, months[i].Timestamp)
		secondTimestamp, errTwo := time.Parse(time.RFC3339, months[j].Timestamp)
		if errOne == nil && errTwo == nil {
			return firstTimestamp.Before(secondTimestamp)
		}
		// Keep the nondeterministic ordering in storage
		a.logger.Error("unable to parse activity log timestamps", "timestamp",
			months[i].Timestamp, "error", errOne, "timestamp", months[j].Timestamp, "error", errTwo)
		return i < j
	})

	// Within each month sort everything by descending order of activity
	for _, month := range months {
		sort.Slice(month.Namespaces, func(i, j int) bool {
			return month.Namespaces[i].Counts.Clients > month.Namespaces[j].Counts.Clients
		})

		for _, ns := range month.Namespaces {
			sort.Slice(ns.Mounts, func(i, j int) bool {
				return ns.Mounts[i].Counts.Clients > ns.Mounts[j].Counts.Clients
			})
		}

		sort.Slice(month.NewClients.Namespaces, func(i, j int) bool {
			return month.NewClients.Namespaces[i].Counts.Clients > month.NewClients.Namespaces[j].Counts.Clients
		})

		for _, ns := range month.NewClients.Namespaces {
			sort.Slice(ns.Mounts, func(i, j int) bool {
				return ns.Mounts[i].Counts.Clients > ns.Mounts[j].Counts.Clients
			})
		}
	}
}

const (
	noMountAccessor     = "no mount accessor (pre-1.10 upgrade?)"
	noMountPath         = "no mount path (pre-1.10 upgrade?)"
	DeletedMountFmt     = "deleted mount; accessor %q"
	DeletedMountPath    = "deleted mount"
	DeletedNamespaceFmt = "deleted namespace %q"
)

// mountAccessorToMountPath transforms the mount accessor to the mount path
// returns a placeholder string if the mount accessor is empty or deleted
func (a *ActivityLog) mountAccessorToMountPath(mountAccessor string) string {
	var displayPath string
	if mountAccessor == "" {
		displayPath = noMountAccessor
	} else {
		valResp := a.core.router.ValidateMountByAccessor(mountAccessor)
		if valResp == nil {
			displayPath = fmt.Sprintf(DeletedMountFmt, mountAccessor)
		} else {
			displayPath = valResp.MountPath
			if !strings.HasSuffix(displayPath, "/") {
				displayPath += "/"
			}
		}
	}
	return displayPath
}

// mountPathToMountType transforms the mount path to the mount type
// returns a placeholder string if the mount path is empty or deleted
func (a *ActivityLog) mountPathToMountType(ctx context.Context, mountPath string) string {
	var mountType string
	if mountPath == "" {
		mountType = noMountPath
	} else {
		path, valResp := a.core.router.MatchingMountAndEntry(ctx, mountPath)
		if path == "" {
			mountType = DeletedMountPath
		} else {
			mountType = valResp.Type
			if !strings.HasSuffix(mountType, "/") {
				mountType += "/"
			}
		}
	}
	return mountType
}

type singleTypeSegmentReader struct {
	basePath         string
	startTime        time.Time
	paths            []string
	currentPathIndex int
	a                *ActivityLog
}
type segmentReader struct {
	tokens   *singleTypeSegmentReader
	entities *singleTypeSegmentReader
}

// SegmentReader is an interface that provides methods to read tokens and entities in order
type SegmentReader interface {
	ReadToken(ctx context.Context) (*activity.TokenCount, error)
	ReadEntity(ctx context.Context) (*activity.EntityActivityLog, error)
}

func (a *ActivityLog) NewSegmentFileReader(ctx context.Context, startTime time.Time) (SegmentReader, error) {
	entities, err := a.newSingleTypeSegmentReader(ctx, startTime, activityEntityBasePath)
	if err != nil {
		return nil, err
	}
	tokens, err := a.newSingleTypeSegmentReader(ctx, startTime, activityTokenBasePath)
	if err != nil {
		return nil, err
	}
	return &segmentReader{entities: entities, tokens: tokens}, nil
}

func (a *ActivityLog) newSingleTypeSegmentReader(ctx context.Context, startTime time.Time, prefix string) (*singleTypeSegmentReader, error) {
	basePath := prefix + fmt.Sprint(startTime.Unix()) + "/"
	pathList, err := a.view.List(ctx, basePath)
	if err != nil {
		return nil, err
	}
	return &singleTypeSegmentReader{
		basePath:         basePath,
		startTime:        startTime,
		paths:            pathList,
		currentPathIndex: 0,
		a:                a,
	}, nil
}

func (s *singleTypeSegmentReader) nextValue(ctx context.Context, out proto.Message) error {
	var raw *logical.StorageEntry
	var path string
	for raw == nil {
		if s.currentPathIndex >= len(s.paths) {
			return io.EOF
		}
		path = s.paths[s.currentPathIndex]
		// increment the index to continue iterating for the next read call, even if an error occurs during this call
		s.currentPathIndex++
		var err error
		raw, err = s.a.view.Get(ctx, s.basePath+path)
		if err != nil {
			return err
		}
		if raw == nil {
			s.a.logger.Warn("expected log segment file has been deleted", "startTime", s.startTime, "segmentPath", path)
		}
	}
	err := proto.Unmarshal(raw.Value, out)
	if err != nil {
		return fmt.Errorf("unable to parse segment file %v%v: %w", s.basePath, path, err)
	}
	return nil
}

// ReadToken reads a token from the segment
// If there is none available, then the error will be io.EOF
func (e *segmentReader) ReadToken(ctx context.Context) (*activity.TokenCount, error) {
	out := &activity.TokenCount{}
	err := e.tokens.nextValue(ctx, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadEntity reads an entity from the segment
// If there is none available, then the error will be io.EOF
func (e *segmentReader) ReadEntity(ctx context.Context) (*activity.EntityActivityLog, error) {
	out := &activity.EntityActivityLog{}
	err := e.entities.nextValue(ctx, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// namespaceRecordToCountsResponse converts the record to the ResponseCounts
// type. The function sums entity, non-entity, and secret sync counts to get the
// total client count.
func (a *ActivityLog) countsRecordToCountsResponse(record *activity.CountsRecord) *ResponseCounts {
	response := &ResponseCounts{
		EntityClients:    record.EntityClients,
		NonEntityClients: record.NonEntityClients,
		Clients:          record.EntityClients + record.NonEntityClients + record.SecretSyncs + record.ACMEClients,
		SecretSyncs:      record.SecretSyncs,
		ACMEClients:      record.ACMEClients,
	}
	return response
}

// namespaceRecordToCountsResponse converts the namespace counts to the
// ResponseCounts type. The function sums entity, non-entity, and secret sync
// counts to get the total client count.
func (a *ActivityLog) namespaceRecordToCountsResponse(record *activity.NamespaceRecord) *ResponseCounts {
	return &ResponseCounts{
		EntityClients:    int(record.Entities),
		NonEntityClients: int(record.NonEntityTokens),
		Clients:          int(record.Entities + record.NonEntityTokens + record.SecretSyncs + record.ACMEClients),
		SecretSyncs:      int(record.SecretSyncs),
		ACMEClients:      int(record.ACMEClients),
	}
}

func (a *ActivityLog) GetClientIDsUsageInfo() map[string]struct{} {
	a.clientIDsUsage.clientIDsUsageInfoLock.Lock()
	defer a.clientIDsUsage.clientIDsUsageInfoLock.Unlock()
	return a.clientIDsUsage.clientIDsUsageInfo
}

func (a *ActivityLog) SetClientIDsUsageInfo(inMemClientIDsMap map[string]struct{}) {
	a.clientIDsUsage.clientIDsUsageInfoLock.Lock()
	defer a.clientIDsUsage.clientIDsUsageInfoLock.Unlock()

	a.clientIDsUsage.clientIDsUsageInfo = inMemClientIDsMap
}

// GetclientIDsUsageInfoLoaded gets a.clientIDsUsageInfoLoaded for external tests
func (a *ActivityLog) GetClientIDsUsageInfoLoaded() bool {
	return a.clientIDsUsage.clientIDsUsageInfoLoaded.Load()
}

// SetClientIDsUsageInfoLoaded sets a.clientIDsUsageInfoLoaded for external tests
func (a *ActivityLog) SetClientIDsUsageInfoLoaded(loaded bool) {
	a.clientIDsUsage.clientIDsUsageInfoLoaded.Store(loaded)
}

// SetupClientIDsUsageInfo calls core.setupClientIDsUsageInfo for external tests
func (c *Core) SetupClientIDsUsageInfo(ctx context.Context) {
	c.setupClientIDsUsageInfo(ctx)
}
