/**
 * Loading Skeleton Components - Reusable loading states
 */

export function StatCardSkeleton() {
  return (
    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 animate-pulse">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="h-4 bg-gray-700 rounded w-24 mb-2"></div>
          <div className="h-8 bg-gray-700 rounded w-16"></div>
        </div>
        <div className="w-10 h-10 bg-gray-700 rounded"></div>
      </div>
    </div>
  );
}

export function ChartSkeleton() {
  return (
    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 animate-pulse">
      <div className="h-5 bg-gray-700 rounded w-48 mb-4"></div>
      <div className="h-64 bg-gray-700 rounded"></div>
    </div>
  );
}

export function TableRowSkeleton() {
  return (
    <tr className="animate-pulse">
      <td className="px-4 py-3">
        <div className="w-4 h-4 bg-gray-700 rounded"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-24"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-32"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-20"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-16"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-16"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-16"></div>
      </td>
      <td className="px-4 py-3">
        <div className="h-4 bg-gray-700 rounded w-12"></div>
      </td>
    </tr>
  );
}

export function CardSkeleton() {
  return (
    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 animate-pulse">
      <div className="h-5 bg-gray-700 rounded w-32 mb-3"></div>
      <div className="h-4 bg-gray-700 rounded w-full mb-2"></div>
      <div className="h-4 bg-gray-700 rounded w-3/4"></div>
    </div>
  );
}

export function RemediationCardSkeleton() {
  return (
    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 animate-pulse">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="h-5 bg-gray-700 rounded w-32 mb-2"></div>
          <div className="h-4 bg-gray-700 rounded w-24"></div>
        </div>
        <div className="w-16 h-8 bg-gray-700 rounded"></div>
      </div>
      <div className="h-16 bg-gray-700 rounded mb-3"></div>
      <div className="space-y-2">
        <div className="h-4 bg-gray-700 rounded w-full"></div>
        <div className="h-4 bg-gray-700 rounded w-full"></div>
      </div>
    </div>
  );
}
