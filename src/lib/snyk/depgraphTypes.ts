export interface DepgraphGetResponseType {
    /**
     * The dependency-graph object
     */
    depGraph: {
        /**
         * The scheme version of the depGraph object
         */
        schemaVersion: string;
        /**
         * The package manager of the project
         */
        pkgManager: {
            /**
             * The name of the package manager
             */
            name: string;
            /**
             * The version of the package manager
             */
            version?: string;
            repositories?: {
                alias: string;
            }[];
        };
        /**
         * A list of dependencies in the project
         */
        pkgs: {
            /**
             * The internal id of the package
             */
            id: string;
            info: {
                /**
                 * The name of the package
                 */
                name: string;
                /**
                 * The version of the package
                 */
                version?: string;
            };
        }[];
        /**
         * A directional graph of the packages in the project
         */
        graph: {
            /**
             * The internal id of the root node
             */
            rootNodeId: string;
            /**
             * A list of the first-level packages
             */
            nodes?: {
                /**
                 * The internal id of the node
                 */
                nodeId: string;
                /**
                 * The id of the package
                 */
                pkgId: string;
                /**
                 * A list of the direct dependencies of the package
                 */
                deps: {
                    /**
                     * The id of the node
                     */
                    nodeId: string;
                }[];
            }[];
        };
    };
}